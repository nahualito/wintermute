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

import json
import logging
import os
from pathlib import Path
from typing import Any

from .provider import LLMRegistry, Router, llms
from .providers.bedrock_provider import register as register_bedrock
from .providers.groq_provider import register as register_groq
from .providers.huggingface_provider import register as register_huggingface
from .providers.openai_provider import register as register_openai
from .providers.rag_provider import RAGProvider

log = logging.getLogger(__name__)


def bootstrap_rags(registry: LLMRegistry) -> list[RAGProvider]:
    """Scan knowledge bases and external repos for LlamaIndex storage and register them as RAGProviders."""
    search_paths = ["./knowledge_bases", "./external_repos"]
    new_providers: list[RAGProvider] = []

    # Defaults from environment
    default_base = os.getenv("DEFAULT_RAG_PROVIDER", "bedrock")
    default_embed_provider = os.getenv("DEFAULT_EMBED_PROVIDER", "bedrock")
    default_embed_model = os.getenv(
        "DEFAULT_EMBED_MODEL", "amazon.titan-embed-text-v2:0"
    )
    qdrant_api_key = os.getenv("QDRANT_API_KEY", "")

    for path_str in search_paths:
        base_path = Path(path_str)
        if not base_path.exists():
            continue

        for folder in base_path.iterdir():
            if not folder.is_dir():
                continue

            config_file = folder / "rag_config.json"
            storage_db = folder / "storage_db"

            # Parse config first to determine vector store type
            config: dict[str, Any] = {}
            if config_file.exists():
                try:
                    with open(config_file, "r") as f:
                        config = json.load(f)
                except Exception as e:
                    log.error(f"Failed to load config for rag-{folder.name}: {e}")
                    continue

            vector_store_type = config.get("vector_store_type", "local")
            has_local_storage = storage_db.exists() and storage_db.is_dir()
            has_qdrant_config = vector_store_type == "qdrant"

            if not has_local_storage and not has_qdrant_config:
                continue  # skip — no usable storage

            provider_id = f"rag-{folder.name}"

            # Read config fields with backward-compat fallback
            base_id = config.get("base_provider_id", default_base)
            embed_id = config.get("embed_provider_id", default_embed_provider)
            embed_model_id = config.get(
                "embedding_model", config.get("embed_model_id", default_embed_model)
            )
            rag_description = config.get("description", "")

            # Qdrant fields
            qdrant_url = config.get("qdrant_url", "")
            db_path = config.get("db_path", "")
            qdrant_collection = config.get("qdrant_collection_name", folder.name)

            # Metadata (logged but not used for bootstrap logic)
            document_types: list[str] = config.get("document_types", [])
            created_at = config.get("created_at", "")

            log.info(
                f"Bootstrapping RAG provider: {provider_id} (Base: {base_id}, Embed: {embed_id})"
            )

            try:
                # Resolve dependencies
                try:
                    base_provider = registry.get(base_id)
                except KeyError:
                    log.error(
                        f"Base provider '{base_id}' not found for RAG {provider_id}"
                    )
                    continue

                embed_provider = None
                try:
                    embed_provider = registry.get(embed_id)
                except KeyError:
                    log.warning(
                        f"Embedding provider '{embed_id}' not found. LlamaIndex may fail if embeddings are needed."
                    )

                # Build vector store for Qdrant KBs
                vector_store = None
                if vector_store_type == "qdrant":
                    from llama_index.vector_stores.qdrant import QdrantVectorStore
                    from qdrant_client import QdrantClient

                    if qdrant_url:
                        # Remote Qdrant server
                        qclient = QdrantClient(
                            url=qdrant_url,
                            api_key=qdrant_api_key or None,
                        )
                    elif db_path:
                        # Local on-disk Qdrant database
                        qclient = QdrantClient(path=db_path)
                    else:
                        # Local Qdrant inside the KB folder itself
                        qclient = QdrantClient(path=str(folder / "qdrant_db"))

                    vector_store = QdrantVectorStore(
                        client=qclient,
                        collection_name=qdrant_collection,
                    )
                    log.info(
                        f"Using Qdrant vector store for {provider_id}: "
                        f"url={qdrant_url or 'local'}, collection={qdrant_collection}"
                    )

                if document_types:
                    log.info(f"  Document types: {document_types}")
                if created_at:
                    log.info(f"  Created at: {created_at}")

                rag_provider = RAGProvider(
                    name=provider_id,
                    base_provider=base_provider,
                    persist_dir=str(storage_db),
                    embed_provider=embed_provider,
                    embed_model_id=embed_model_id,
                    description=rag_description,
                    vector_store=vector_store,
                )
                registry.register(rag_provider)
                new_providers.append(rag_provider)
            except Exception as e:
                log.error(f"Failed to bootstrap RAG provider {provider_id}: {e}")

    return new_providers


def init_router() -> Router:
    """Initialize and return a Router with registered LLM providers."""
    # Register all providers first
    register_bedrock(region=os.getenv("AWS_REGION", "us-east-1"))
    register_groq(api_key=os.getenv("GROQ_API_KEY"))
    register_openai(api_key=os.getenv("OPENAI_API_KEY"))
    register_huggingface(as_name="local_embedder")

    # Bootstrap RAGs dynamically
    try:
        bootstrap_rags(llms)
    except Exception as e:
        log.warning(f"Could not bootstrap RAGs: {e}")

    # Make Bedrock the primary
    return Router(
        default_provider="bedrock", default_model=os.getenv("BEDROCK_MODEL_ID")
    )
