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
from typing import Any, Iterable, Optional, cast

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None  # type: ignore

from wintermute.ai.provider import ModelInfo, llms
from wintermute.ai.types import ChatRequest, ChatResponse

log = logging.getLogger(__name__)


class HuggingFaceProvider:
    """Local HuggingFace embedding provider using sentence-transformers."""

    def __init__(self, name: str = "local_embedder") -> None:
        self._name = name
        self._models: dict[str, Any] = {}
        if SentenceTransformer is None:
            log.warning(
                "sentence-transformers not installed. HuggingFaceProvider will not work."
            )

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Local HuggingFace sentence-transformers for embeddings only."

    def list_models(self) -> list[ModelInfo]:
        """Returns a list of common embedding models supported."""
        return [
            ModelInfo(
                name="all-MiniLM-L6-v2",
                family="BERT",
                context_window=512,
                supports_tools=False,
                supports_json=False,
                supports_stream=False,
            ),
            ModelInfo(
                name="BAAI/bge-small-en-v1.5",
                family="BERT",
                context_window=512,
                supports_tools=False,
                supports_json=False,
                supports_stream=False,
            ),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        raise NotImplementedError(
            "HuggingFace provider is currently for embeddings only."
        )

    def embed(
        self, texts: Iterable[str], model: Optional[str] = None
    ) -> list[list[float]]:
        """
        Embeds texts using a local SentenceTransformer model.
        Args:
            texts: List of strings to embed.
            model: Model name/path (default: 'all-MiniLM-L6-v2').
        """
        if SentenceTransformer is None:
            raise ImportError("sentence-transformers not installed.")

        model_name = model or "all-MiniLM-L6-v2"

        if model_name not in self._models:
            log.info(f"Loading local embedding model: {model_name}")
            self._models[model_name] = SentenceTransformer(model_name)

        transformer = self._models[model_name]
        # encode returns numpy array or list of numpy arrays; convert to list[list[float]]
        embeddings = transformer.encode(list(texts), convert_to_numpy=True)
        return cast("list[list[float]]", embeddings.tolist())

    def count_tokens(self, text: str, model: Optional[str] = None) -> int:
        """
        Returns estimated token count. For now, using a simple heuristic
        as exact tokenization requires the specific tokenizer.
        """
        if SentenceTransformer is None:
            return len(text.split())

        model_name = model or "all-MiniLM-L6-v2"
        # If model is loaded, we can use its tokenizer
        if model_name in self._models:
            tokenizer = self._models[model_name].tokenizer
            return len(tokenizer.tokenize(text))

        # Fallback heuristic
        return len(text.split())


def register(as_name: str = "local_embedder") -> None:
    """Registers the HuggingFaceProvider."""
    try:
        provider = HuggingFaceProvider(name=as_name)
        llms.register(provider)
        log.info(f"Registered HuggingFaceProvider as '{as_name}'")
    except Exception as e:
        log.error(f"Failed to register HuggingFaceProvider: {e}")
