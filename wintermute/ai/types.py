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
    role: Role
    content: str
    tool_name: Optional[str] = None
    tool_call_id: Optional[str] = None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JSONObject
    # Optional: you can validate model's JSON outputs against this if you want
    output_schema: Optional[JSONObject] = None


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: JSONObject  # parsed JSON args


@dataclass(frozen=True)
class ChatRequest:
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
    content: str
    tool_calls: Optional[list[ToolCall]] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[int] = None
