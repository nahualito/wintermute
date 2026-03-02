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

    # Mock json.load — uses new field names with backward compat
    with patch("builtins.open", new_callable=MagicMock) as mock_open:
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        with patch("json.load") as mock_json_load:
            mock_json_load.return_value = {
                "base_provider_id": "mock-base",
                "embed_provider_id": "mock-embed",
                "embedding_model": "custom-embed-model",
                "description": "Test KB with custom description.",
                "document_types": ["pdf", "text"],
                "created_at": "2025-06-15T00:00:00Z",
            }

            # Run bootstrap
            bootstrap_rags(mock_registry)

            # Verify RAGProvider init
            mock_rag_provider.assert_called_once()
            _, kwargs = mock_rag_provider.call_args
            assert kwargs["name"] == "rag-test_kb"
            assert kwargs["embed_model_id"] == "custom-embed-model"
            assert kwargs["description"] == "Test KB with custom description."
            assert kwargs["vector_store"] is None

            # Verify registration
            mock_registry.register.assert_called_once()


@patch("wintermute.ai.bootstrap.Path")
@patch("wintermute.ai.bootstrap.RAGProvider")
def test_bootstrap_with_legacy_embed_model_id(
    mock_rag_provider: MagicMock, mock_path: MagicMock, mock_registry: MagicMock
) -> None:
    """Verify that the old embed_model_id field still works as fallback."""
    mock_base_path = MagicMock()
    mock_base_path.exists.return_value = True

    mock_folder = MagicMock()
    mock_folder.is_dir.return_value = True
    mock_folder.name = "legacy_kb"

    mock_storage = MagicMock()
    mock_storage.exists.return_value = True
    mock_storage.is_dir.return_value = True

    mock_config = MagicMock()
    mock_config.exists.return_value = True

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

    with patch("builtins.open", new_callable=MagicMock) as mock_open:
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        with patch("json.load") as mock_json_load:
            # Old-style config with embed_model_id (no embedding_model)
            mock_json_load.return_value = {
                "base_provider_id": "mock-base",
                "embed_provider_id": "mock-embed",
                "embed_model_id": "legacy-embed-model",
                "description": "Legacy KB.",
            }

            bootstrap_rags(mock_registry)

            mock_rag_provider.assert_called_once()
            _, kwargs = mock_rag_provider.call_args
            assert kwargs["embed_model_id"] == "legacy-embed-model"


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
        assert kwargs["description"] == ""  # no config file → empty string
        assert kwargs["vector_store"] is None


@patch("wintermute.ai.bootstrap.Path")
@patch("wintermute.ai.bootstrap.RAGProvider")
def test_bootstrap_with_qdrant_config(
    mock_rag_provider: MagicMock, mock_path: MagicMock, mock_registry: MagicMock
) -> None:
    """Qdrant KB with remote URL — storage_db/ is NOT required."""
    mock_base_path = MagicMock()
    mock_base_path.exists.return_value = True

    mock_folder = MagicMock()
    mock_folder.is_dir.return_value = True
    mock_folder.name = "qdrant_kb"

    mock_storage = MagicMock()
    mock_storage.exists.return_value = False  # No storage_db
    mock_storage.is_dir.return_value = False

    mock_config = MagicMock()
    mock_config.exists.return_value = True

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

    with patch("builtins.open", new_callable=MagicMock) as mock_open:
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        with patch("json.load") as mock_json_load:
            mock_json_load.return_value = {
                "base_provider_id": "mock-base",
                "embed_provider_id": "mock-embed",
                "embedding_model": "BAAI/bge-small-en-v1.5",
                "vector_store_type": "qdrant",
                "qdrant_url": "http://localhost:6333",
                "qdrant_collection_name": "test_collection",
                "document_types": ["pdf", "markdown"],
                "created_at": "2026-03-01T12:00:00Z",
                "description": "Qdrant-backed KB.",
            }

            # Mock Qdrant imports
            with (
                patch(
                    "wintermute.ai.bootstrap.QdrantClient",
                    create=True,
                ) as mock_qclient_cls,
                patch(
                    "wintermute.ai.bootstrap.QdrantVectorStore",
                    create=True,
                ) as mock_qvs_cls,
            ):
                # Patch the lazy imports inside bootstrap_rags
                mock_qclient = MagicMock()
                mock_qclient_cls.return_value = mock_qclient
                mock_qvs = MagicMock()
                mock_qvs_cls.return_value = mock_qvs

                with (
                    patch.dict(
                        "sys.modules",
                        {
                            "qdrant_client": MagicMock(QdrantClient=mock_qclient_cls),
                            "llama_index.vector_stores.qdrant": MagicMock(
                                QdrantVectorStore=mock_qvs_cls
                            ),
                        },
                    ),
                ):
                    bootstrap_rags(mock_registry)

                    # Verify RAGProvider was created with the vector store
                    mock_rag_provider.assert_called_once()
                    _, kwargs = mock_rag_provider.call_args
                    assert kwargs["name"] == "rag-qdrant_kb"
                    assert kwargs["embed_model_id"] == "BAAI/bge-small-en-v1.5"
                    assert kwargs["description"] == "Qdrant-backed KB."
                    assert kwargs["vector_store"] is mock_qvs

                    # Verify QdrantClient was called with url
                    mock_qclient_cls.assert_called_once_with(
                        url="http://localhost:6333", api_key=None
                    )

                    # Verify QdrantVectorStore was created with correct collection
                    mock_qvs_cls.assert_called_once_with(
                        client=mock_qclient, collection_name="test_collection"
                    )


@patch("wintermute.ai.bootstrap.Path")
@patch("wintermute.ai.bootstrap.RAGProvider")
def test_bootstrap_with_local_qdrant(
    mock_rag_provider: MagicMock, mock_path: MagicMock, mock_registry: MagicMock
) -> None:
    """Qdrant KB with local db_path instead of remote URL."""
    mock_base_path = MagicMock()
    mock_base_path.exists.return_value = True

    mock_folder = MagicMock()
    mock_folder.is_dir.return_value = True
    mock_folder.name = "local_qdrant_kb"

    mock_storage = MagicMock()
    mock_storage.exists.return_value = False
    mock_storage.is_dir.return_value = False

    mock_config = MagicMock()
    mock_config.exists.return_value = True

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

    with patch("builtins.open", new_callable=MagicMock) as mock_open:
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        with patch("json.load") as mock_json_load:
            mock_json_load.return_value = {
                "base_provider_id": "mock-base",
                "embed_provider_id": "mock-embed",
                "embedding_model": "BAAI/bge-small-en-v1.5",
                "vector_store_type": "qdrant",
                "db_path": "/data/my_local_qdrant",
                "qdrant_collection_name": "local_collection",
                "description": "Local Qdrant KB.",
            }

            mock_qclient_cls = MagicMock()
            mock_qclient = MagicMock()
            mock_qclient_cls.return_value = mock_qclient
            mock_qvs_cls = MagicMock()
            mock_qvs = MagicMock()
            mock_qvs_cls.return_value = mock_qvs

            with patch.dict(
                "sys.modules",
                {
                    "qdrant_client": MagicMock(QdrantClient=mock_qclient_cls),
                    "llama_index.vector_stores.qdrant": MagicMock(
                        QdrantVectorStore=mock_qvs_cls
                    ),
                },
            ):
                bootstrap_rags(mock_registry)

                mock_rag_provider.assert_called_once()
                _, kwargs = mock_rag_provider.call_args
                assert kwargs["name"] == "rag-local_qdrant_kb"
                assert kwargs["vector_store"] is mock_qvs

                # Verify QdrantClient was called with path (not url)
                mock_qclient_cls.assert_called_once_with(path="/data/my_local_qdrant")
