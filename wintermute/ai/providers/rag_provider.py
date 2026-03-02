# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long
#
# MIT License
#
# Copyright (c) 2024,2025 Enrique Alfonso Sanchez Montellano (nahualito)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from llama_index.core import (
    StorageContext,
    load_index_from_storage,
)
from llama_index.core.base.llms.types import CompletionResponse
from llama_index.core.embeddings import BaseEmbedding
from llama_index.core.indices.vector_store import VectorStoreIndex
from llama_index.core.llms import LLM
from llama_index.core.query_engine import BaseQueryEngine
from llama_index.core.vector_stores.types import BasePydanticVectorStore

from wintermute.ai.provider import LLMProvider, ModelInfo
from wintermute.ai.types import ChatRequest, ChatResponse, Message

log = logging.getLogger(__name__)


class LlamaIndexEmbeddingWrapper(BaseEmbedding):
    """Wraps a Wintermute LLMProvider to be used as a LlamaIndex embedding model."""

    _provider: LLMProvider = None  # type: ignore
    _model: str = ""

    def __init__(self, provider: LLMProvider, model_name: str) -> None:
        super().__init__()
        self._provider = provider
        self._model = model_name

    def _get_query_embedding(self, query: str) -> list[float]:
        embeddings = self._provider.embed([query], model=self._model)
        if not embeddings:
            raise ValueError("Embedding provider returned empty list")
        return embeddings[0]

    async def _aget_query_embedding(self, query: str) -> list[float]:
        return self._get_query_embedding(query)

    def _get_text_embedding(self, text: str) -> list[float]:
        embeddings = self._provider.embed([text], model=self._model)
        if not embeddings:
            raise ValueError("Embedding provider returned empty list")
        return embeddings[0]

    async def _aget_text_embedding(self, text: str) -> list[float]:
        return self._get_text_embedding(text)

    def _get_text_embeddings(self, texts: list[str]) -> list[list[float]]:
        return self._provider.embed(texts, model=self._model)


class LlamaIndexLLMWrapper(LLM):
    """Wraps a Wintermute LLMProvider to be used within LlamaIndex."""

    def __init__(self, provider: LLMProvider, model: Optional[str] = None) -> None:
        super().__init__()
        self._provider = provider
        self._model = model

    @property
    def metadata(self) -> Any:
        from llama_index.core.base.llms.types import LLMMetadata

        return LLMMetadata()

    def complete(
        self, prompt: str, formatted: bool = False, **kwargs: Any
    ) -> CompletionResponse:
        req = ChatRequest(
            messages=[Message(role="user", content=prompt)],
            model=self._model,
        )
        resp = self._provider.chat(req)
        return CompletionResponse(text=resp.content)

    def stream_complete(
        self, prompt: str, formatted: bool = False, **kwargs: Any
    ) -> Any:
        raise NotImplementedError("Streaming not supported in wrapper")

    def chat(self, messages: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("Chat not supported in wrapper")

    def stream_chat(self, messages: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("Streaming chat not supported in wrapper")

    async def acomplete(
        self, prompt: str, formatted: bool = False, **kwargs: Any
    ) -> CompletionResponse:
        return self.complete(prompt, formatted, **kwargs)

    async def achat(self, messages: Any, **kwargs: Any) -> Any:
        return self.chat(messages, **kwargs)

    async def astream_chat(self, messages: Any, **kwargs: Any) -> Any:
        return self.stream_chat(messages, **kwargs)

    async def astream_complete(
        self, prompt: str, formatted: bool = False, **kwargs: Any
    ) -> Any:
        return self.stream_complete(prompt, formatted, **kwargs)


_DEFAULT_RAG_DESCRIPTION = "Custom RAG knowledge base (No description provided)."


class RAGProvider:
    """RAG implementation that conforms to LLMProvider."""

    def __init__(
        self,
        name: str,
        base_provider: LLMProvider,
        persist_dir: str,
        embed_provider: Optional[LLMProvider] = None,
        embed_model_id: str = "amazon.titan-embed-text-v2:0",
        description: str = "",
        vector_store: BasePydanticVectorStore | None = None,
    ) -> None:
        self._name = name
        self._description = description or _DEFAULT_RAG_DESCRIPTION
        self.base_provider = base_provider
        self.persist_dir = persist_dir

        # Configure embedding model
        embed_model: Optional[BaseEmbedding] = None
        if embed_provider:
            embed_model = LlamaIndexEmbeddingWrapper(
                provider=embed_provider, model_name=embed_model_id
            )

        # Load index
        if vector_store is not None:
            # External vector store (Qdrant) — index lives in the database
            self.index: VectorStoreIndex = VectorStoreIndex.from_vector_store(
                vector_store,
                embed_model=embed_model,
            )
        else:
            # Local file-based storage (backward compatible)
            storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
            self.index = load_index_from_storage(
                storage_context,
                embed_model=embed_model,
            )  # type: ignore

        # Create local query engine without global Settings
        self.query_engine: BaseQueryEngine = self.index.as_query_engine(
            llm=LlamaIndexLLMWrapper(base_provider),
            embed_model=embed_model,
        )

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    def list_models(self) -> list[ModelInfo]:
        return self.base_provider.list_models()

    def chat(self, req: ChatRequest) -> ChatResponse:
        """Augment prompt with RAG and call base provider."""
        if not req.messages:
            return self.base_provider.chat(req)

        last_msg = req.messages[-1].content
        log.info(f"[RAG:{self.name}] Querying local index for: {last_msg[:50]}...")

        # Retrieve context
        response = self.query_engine.query(last_msg)
        context = str(response)

        # Augment the prompt
        augmented_content = (
            f"Context information is below.\n---------------------\n{context}\n---------------------\n"
            f"Using the context above, answer the query.\n"
            f"Query: {last_msg}\nAnswer: "
        )

        # Create new request with augmented message
        new_messages = list(req.messages[:-1])
        new_messages.append(Message(role="user", content=augmented_content))

        new_req = ChatRequest(
            messages=new_messages,
            model=req.model,
            temperature=req.temperature,
            max_tokens=req.max_tokens,
            tools=req.tools,
            tool_choice=req.tool_choice,
            response_format=req.response_format,
            stream=req.stream,
            task_tag=req.task_tag,
        )

        return self.base_provider.chat(new_req)

    def embed(
        self, texts: Iterable[str], model: Optional[str] = None
    ) -> list[list[float]]:
        return self.base_provider.embed(texts, model)

    def count_tokens(self, text: str, model: Optional[str] = None) -> int:
        return self.base_provider.count_tokens(text, model)
