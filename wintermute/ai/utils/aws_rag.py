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

import logging
import os

from llama_index.core import (
    PromptTemplate,
    Settings,
    StorageContext,
    load_index_from_storage,
)
from llama_index.core.query_engine import BaseQueryEngine
from llama_index.embeddings.bedrock import BedrockEmbedding
from llama_index.llms.bedrock import Bedrock

from wintermute.ai.json_types import JSONObject

from .tool_factory import register_tools

log = logging.getLogger(__name__)

# --- Configuration ---
PERSIST_DIR = "./storage_db"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Global singleton for the query engine
_QUERY_ENGINE: BaseQueryEngine | None = None


def _initialize_rag_engine() -> BaseQueryEngine:
    """Initializes LlamaIndex with Bedrock and loads the vector DB."""
    global _QUERY_ENGINE
    if _QUERY_ENGINE:
        return _QUERY_ENGINE

    log.info("[RAG] Initializing Hardware Oracle...")

    # 1. Setup Bedrock for LlamaIndex (Mirroring your Wintermute BedrockProvider)
    Settings.llm = Bedrock(
        model="anthropic.claude-3-5-sonnet-20240620-v1:0",
        region_name=AWS_REGION,
        temperature=0.1,
    )
    Settings.embed_model = BedrockEmbedding(
        model_name="amazon.titan-embed-text-v2:0", region_name=AWS_REGION
    )

    # 2. Load the Index (Assumes you ran the ingestion script we built earlier!)
    if not os.path.exists(PERSIST_DIR):
        log.error(
            f"RAG Database not found at {PERSIST_DIR}. Run ingestion script first."
        )
        raise FileNotFoundError(
            f"RAG Database not found at {PERSIST_DIR}. Run ingestion script first."
        )

    storage_context = StorageContext.from_defaults(persist_dir=PERSIST_DIR)
    index = load_index_from_storage(storage_context)

    # 3. Setup Custom Prompt for Security Context
    security_prompt = PromptTemplate(
        "Context information is below.\n---------------------\n{context_str}\n---------------------\n"
        "You are a Hardware Security Expert. Using the context above, answer the query.\n"
        "Cite specific values (voltages, addresses) from the manuals.\n"
        "Query: {query_str}\nAnswer: "
    )

    _QUERY_ENGINE = index.as_query_engine(
        similarity_top_k=5, text_qa_template=security_prompt
    )
    return _QUERY_ENGINE


def query_manuals_handler(args: JSONObject) -> JSONObject:
    """Handler function that receives JSON args from the LLM."""
    query_text = args.get("query")
    if not query_text:
        return {"error": "No query provided"}

    try:
        engine = _initialize_rag_engine()
        response = engine.query(query_text)
        return {"result": str(response)}
    except Exception as e:
        return {"error": str(e)}


# Register immediately upon import
register_tools([query_manuals_handler])
