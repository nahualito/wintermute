# -*- coding: utf-8 -*-
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from wintermute.ai.provider import ModelInfo
from wintermute.ai.providers.rag_provider import RAGProvider
from wintermute.ai.types import ChatRequest, ChatResponse, Message


@pytest.fixture
def mock_base_provider() -> MagicMock:
    provider = MagicMock()
    provider.name = "mock-base"
    provider.list_models.return_value = [ModelInfo("m1", "f1", 100, True, True, True)]
    provider.chat.return_value = ChatResponse(content="Mocked answer")
    return provider


@pytest.fixture
def mock_llama_index() -> Generator[tuple[MagicMock, MagicMock], None, None]:
    with (
        patch("wintermute.ai.providers.rag_provider.StorageContext") as _mock_sc,
        patch(
            "wintermute.ai.providers.rag_provider.load_index_from_storage"
        ) as mock_load,
    ):
        mock_index = MagicMock()
        mock_query_engine = MagicMock()
        mock_query_engine.query.return_value = "Retrieved context"
        mock_index.as_query_engine.return_value = mock_query_engine
        mock_load.return_value = mock_index

        yield mock_index, mock_query_engine


def test_rag_provider_chat(
    mock_base_provider: MagicMock, mock_llama_index: tuple[MagicMock, MagicMock]
) -> None:
    mock_index, mock_query_engine = mock_llama_index

    rag = RAGProvider(
        name="test-rag", base_provider=mock_base_provider, persist_dir="/tmp/dummy-db"
    )

    req = ChatRequest(messages=[Message(role="user", content="What is the voltage?")])
    resp = rag.chat(req)

    assert resp.content == "Mocked answer"
    # Verify query engine was called
    mock_query_engine.query.assert_called_once_with("What is the voltage?")

    # Verify base provider was called with augmented prompt
    args, _ = mock_base_provider.chat.call_args
    augmented_req = args[0]
    assert "Context information is below" in augmented_req.messages[-1].content
    assert "Retrieved context" in augmented_req.messages[-1].content
    assert "What is the voltage?" in augmented_req.messages[-1].content


def test_rag_provider_delegation(
    mock_base_provider: MagicMock, mock_llama_index: tuple[MagicMock, MagicMock]
) -> None:
    rag = RAGProvider(
        name="test-rag", base_provider=mock_base_provider, persist_dir="/tmp/dummy-db"
    )

    assert rag.name == "test-rag"
    assert rag.list_models()[0].name == "m1"

    rag.count_tokens("hello")
    mock_base_provider.count_tokens.assert_called_once_with("hello", None)


@patch("wintermute.ai.providers.rag_provider.LlamaIndexEmbeddingWrapper")
def test_rag_provider_with_embeddings(
    mock_embed_wrapper: MagicMock,
    mock_base_provider: MagicMock,
    mock_llama_index: tuple[MagicMock, MagicMock],
) -> None:
    mock_index, mock_query_engine = mock_llama_index
    mock_embed_provider = MagicMock()
    mock_embed_provider.name = "mock-embed"

    _rag = RAGProvider(
        name="test-rag",
        base_provider=mock_base_provider,
        persist_dir="/tmp/dummy-db",
        embed_provider=mock_embed_provider,
        embed_model_id="custom-embed-v1",
    )

    # Verify wrapper init
    mock_embed_wrapper.assert_called_once_with(
        provider=mock_embed_provider, model_name="custom-embed-v1"
    )

    # Verify index query engine setup uses the wrapper
    mock_index.as_query_engine.assert_called_once()
    _, kwargs = mock_index.as_query_engine.call_args
    assert kwargs["embed_model"] == mock_embed_wrapper.return_value
