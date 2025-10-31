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

from dataclasses import dataclass
from typing import Literal, Optional, Sequence

from .json_types import JSONObject

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True)
class Message:
    """A message in a chat conversation.

    Attributes:
        role (Role): The role of the message sender.
        content (str): The content of the message.
        tool_name (Optional[str]): Name of the tool if role is "tool".
        tool_call_id (Optional[str]): ID of the tool call if role is "tool".
    """

    role: Role
    content: str
    tool_name: Optional[str] = None
    tool_call_id: Optional[str] = None


@dataclass(frozen=True)
class ToolSpec:
    """Specification for a tool that can be called by the LLM.

    Attributes:
        name (str): Name of the tool.
        description (str): Description of the tool's purpose.
        input_schema (JSONObject): JSON schema defining the tool's input.
        output_schema (Optional[JSONObject]): Optional JSON schema for the tool's output.
    """

    name: str
    description: str
    input_schema: JSONObject
    # Optional: you can validate model's JSON outputs against this if you want
    output_schema: Optional[JSONObject] = None


@dataclass(frozen=True)
class ToolCall:
    """A tool call made by the LLM during chat completion.

    Attributes:
        id (str): Unique identifier for the tool call.
        name (str): Name of the tool being called.
        arguments (JSONObject): The arguments passed to the tool as a JSON object.
    """

    id: str
    name: str
    arguments: JSONObject  # parsed JSON args


@dataclass(frozen=True)
class ChatRequest:
    """A request for chat completion.

    Attributes:
        messages (list[Message]): The list of messages in the conversation.
        model (Optional[str]): The model to use for completion.
        temperature (float): Sampling temperature for response generation.
        max_tokens (Optional[int]): Maximum tokens to generate in the response.
        tools (Optional[Sequence[ToolSpec]]): Tools available for the LLM to call.
        tool_choice (Literal["auto", "none", "required"]): Tool calling behavior.
        response_format (Literal["text", "json"]): Desired response format.
        stream (bool): Whether to stream the response.
        task_tag (Optional[str]): Optional tag for tracking the request.
    """

    messages: list[Message]
    model: Optional[str] = None
    temperature: float = 0.2
    max_tokens: Optional[int] = None
    tools: Optional[Sequence[ToolSpec]] = None
    tool_choice: Literal["auto", "none", "required"] = "auto"
    response_format: Literal["text", "json"] = "text"
    stream: bool = False
    task_tag: Optional[str] = None


@dataclass(frozen=True)
class ChatResponse:
    """A response from a chat completion.

    Attributes:
        content (str): The content of the response.
        tool_calls (Optional[list[ToolCall]]): List of tool calls made by the LLM.
        model (Optional[str]): The model used for the response.
        provider (Optional[str]): The provider of the model.
        prompt_tokens (Optional[int]): Number of tokens in the prompt.
        completion_tokens (Optional[int]): Number of tokens in the completion.
        latency_ms (Optional[int]): Latency of the request in milliseconds.
    """

    content: str
    tool_calls: Optional[list[ToolCall]] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[int] = None
