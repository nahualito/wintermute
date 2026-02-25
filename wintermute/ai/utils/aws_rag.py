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

from wintermute.ai.json_types import JSONObject
from wintermute.ai.provider import llms
from wintermute.ai.types import ChatRequest, Message

from .tool_factory import register_tools

log = logging.getLogger(__name__)


def query_manuals_handler(args: JSONObject) -> JSONObject:
    """Handler function that receives JSON args from the LLM.
    Now delegates to the RAGProvider if available."""
    query_text = args.get("query")
    if not query_text or not isinstance(query_text, str):
        return {"error": "No query provided"}

    # Attempt to find the default RAG provider (e.g. from the bootstrapped ones)
    rag_provider = None
    for p_name in llms.providers():
        if p_name.startswith("rag-"):
            rag_provider = llms.get(p_name)
            break

    if not rag_provider:
        return {
            "error": "No RAG provider found. Ensure knowledge bases are bootstrapped."
        }

    try:
        req = ChatRequest(messages=[Message(role="user", content=query_text)])
        response = rag_provider.chat(req)
        return {"result": response.content}
    except Exception as e:
        log.error(f"Error in query_manuals_handler: {e}")
        return {"error": str(e)}


# Register immediately upon import
register_tools([query_manuals_handler])
