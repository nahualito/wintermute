# -*- coding: utf-8 -*-
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from wintermute.ai.provider import llms
from wintermute.ai.providers.huggingface_provider import HuggingFaceProvider, register


@pytest.fixture
def mock_sentence_transformer() -> Generator[MagicMock, None, None]:
    with patch(
        "wintermute.ai.providers.huggingface_provider.SentenceTransformer"
    ) as mock:
        # Create a mock instance
        instance = MagicMock()
        mock.return_value = instance

        # Mock encode to return a numpy-like object with tolist
        mock_embeddings = MagicMock()
        mock_embeddings.tolist.return_value = [[0.1, 0.2, 0.3]]
        instance.encode.return_value = mock_embeddings

        # Mock tokenizer
        mock_tokenizer = MagicMock()
        mock_tokenizer.tokenize.return_value = ["hello", "world"]
        instance.tokenizer = mock_tokenizer

        yield mock


def test_huggingface_provider_embed(mock_sentence_transformer: MagicMock) -> None:
    provider = HuggingFaceProvider()
    texts = ["hello world"]
    embeddings = provider.embed(texts)

    assert embeddings == [[0.1, 0.2, 0.3]]
    mock_sentence_transformer.assert_called_with("all-MiniLM-L6-v2")
    mock_sentence_transformer.return_value.encode.assert_called_once()


def test_huggingface_provider_caching(mock_sentence_transformer: MagicMock) -> None:
    provider = HuggingFaceProvider()
    provider.embed(["text1"], model="model1")
    provider.embed(["text2"], model="model1")

    # SentenceTransformer should be instantiated only once for "model1"
    mock_sentence_transformer.assert_called_once_with("model1")
    assert mock_sentence_transformer.return_value.encode.call_count == 2


def test_huggingface_provider_chat_error() -> None:
    provider = HuggingFaceProvider()
    with pytest.raises(NotImplementedError):
        provider.chat(MagicMock())


def test_huggingface_provider_count_tokens(
    mock_sentence_transformer: MagicMock,
) -> None:
    provider = HuggingFaceProvider()
    # First call loads the model
    provider.embed(["trigger load"])

    count = provider.count_tokens("hello world")
    assert count == 2
    mock_sentence_transformer.return_value.tokenizer.tokenize.assert_called_with(
        "hello world"
    )


def test_register() -> None:
    with patch.object(llms, "register") as mock_register:
        register("my_local_embedder")
        mock_register.assert_called_once()
        args, _ = mock_register.call_args
        provider = args[0]
        assert isinstance(provider, HuggingFaceProvider)
        assert provider.name == "my_local_embedder"
