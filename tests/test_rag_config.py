# -*- coding: utf-8 -*-
import os
from unittest.mock import MagicMock, patch

import pytest

from wintermute.ai.bootstrap import bootstrap_rags
from wintermute.ai.provider import LLMRegistry


@pytest.fixture
def mock_registry() -> MagicMock:
    registry = MagicMock(spec=LLMRegistry)
    # Mock base provider
    base_provider = MagicMock()
    base_provider.name = "mock-base"

    # Mock embed provider
    embed_provider = MagicMock()
    embed_provider.name = "mock-embed"

    def get_side_effect(name: str) -> MagicMock:
        if name == "mock-base":
            return base_provider
        if name == "mock-embed":
            return embed_provider
        raise KeyError(name)

    registry.get.side_effect = get_side_effect
    return registry


@patch("wintermute.ai.bootstrap.Path")
@patch("wintermute.ai.bootstrap.RAGProvider")
def test_bootstrap_with_config(
    mock_rag_provider: MagicMock, mock_path: MagicMock, mock_registry: MagicMock
) -> None:
    # Setup mock filesystem
    mock_base_path = MagicMock()
    mock_base_path.exists.return_value = True

    mock_folder = MagicMock()
    mock_folder.is_dir.return_value = True
    mock_folder.name = "test_kb"

    mock_storage = MagicMock()
    mock_storage.exists.return_value = True
    mock_storage.is_dir.return_value = True

    mock_config = MagicMock()
    mock_config.exists.return_value = True

    # Configure path behavior
    def path_side_effect(arg: str) -> MagicMock:
        if arg == "./knowledge_bases":
            return mock_base_path
        return MagicMock(exists=lambda: False)

    mock_path.side_effect = path_side_effect
    mock_base_path.iterdir.return_value = [mock_folder]

    def folder_truediv(arg: str) -> MagicMock:
        if arg == "storage_db":
            return mock_storage
        if arg == "rag_config.json":
            return mock_config
        return MagicMock()

    mock_folder.__truediv__.side_effect = folder_truediv

    # Mock json.load
    with patch("builtins.open", new_callable=MagicMock) as mock_open:
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        with patch("json.load") as mock_json_load:
            mock_json_load.return_value = {
                "base_provider_id": "mock-base",
                "embed_provider_id": "mock-embed",
                "embed_model_id": "custom-embed-model",
            }

            # Run bootstrap
            bootstrap_rags(mock_registry)

            # Verify RAGProvider init
            mock_rag_provider.assert_called_once()
            _, kwargs = mock_rag_provider.call_args
            assert kwargs["name"] == "rag-test_kb"
            assert kwargs["embed_model_id"] == "custom-embed-model"

            # Verify registration
            mock_registry.register.assert_called_once()


@patch("wintermute.ai.bootstrap.Path")
@patch("wintermute.ai.bootstrap.RAGProvider")
def test_bootstrap_fallback(
    mock_rag_provider: MagicMock, mock_path: MagicMock, mock_registry: MagicMock
) -> None:
    # Setup mock filesystem - no config file
    mock_base_path = MagicMock()
    mock_base_path.exists.return_value = True

    mock_folder = MagicMock()
    mock_folder.is_dir.return_value = True
    mock_folder.name = "test_kb_default"

    mock_storage = MagicMock()
    mock_storage.exists.return_value = True
    mock_storage.is_dir.return_value = True

    mock_config = MagicMock()
    mock_config.exists.return_value = False

    def path_side_effect(arg: str) -> MagicMock:
        if arg == "./knowledge_bases":
            return mock_base_path
        return MagicMock(exists=lambda: False)

    mock_path.side_effect = path_side_effect
    mock_base_path.iterdir.return_value = [mock_folder]

    def folder_truediv(arg: str) -> MagicMock:
        if arg == "storage_db":
            return mock_storage
        if arg == "rag_config.json":
            return mock_config
        return MagicMock()

    mock_folder.__truediv__.side_effect = folder_truediv

    # Mock env vars
    with patch.dict(
        os.environ,
        {"DEFAULT_RAG_PROVIDER": "mock-base", "DEFAULT_EMBED_PROVIDER": "mock-embed"},
    ):
        bootstrap_rags(mock_registry)

        # Verify defaults used
        mock_rag_provider.assert_called_once()
        _, kwargs = mock_rag_provider.call_args
        assert kwargs["name"] == "rag-test_kb_default"
        assert kwargs["embed_model_id"] == "amazon.titan-embed-text-v2:0"  # default
