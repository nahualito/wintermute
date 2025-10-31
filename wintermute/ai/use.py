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

# wintermute/ai/use.py
from __future__ import annotations

from typing import List, Literal

from .provider import Router
from .types import ChatRequest, ChatResponse, Message, ToolSpec


def simple_chat(router: Router, prompt: str, task_tag: str = "generic") -> str:
    """Simple chat completion using the router.

    Args:
        router (Router): The router to select the LLM provider.
        prompt (str): The user prompt for the chat.
        task_tag (str): Optional task tag for routing. Default is "generic".
    """
    req = ChatRequest(
        messages=[Message(role="user", content=prompt)], task_tag=task_tag
    )
    provider, chosen = router.choose(req)
    resp = provider.chat(chosen)
    return resp.content if resp.content else f"(tool_calls={resp.tool_calls})"


def tool_calling_chat(
    router: Router,
    messages: List[Message],
    tools: List[ToolSpec],
    *,
    tool_choice: Literal["auto", "none", "required"] = "auto",
    response_format: Literal["text", "json"] = "text",
    task_tag: str = "generic",
) -> ChatResponse:
    """Chat completion with tool calling support using the router."""
    req = ChatRequest(
        messages=messages,
        tools=tools,
        tool_choice=tool_choice,
        response_format=response_format,
        task_tag=task_tag,
    )
    provider, chosen = router.choose(req)
    return provider.chat(chosen)
