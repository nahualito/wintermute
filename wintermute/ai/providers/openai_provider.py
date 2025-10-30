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

import time
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, cast

from ..provider import LLMProvider, ModelInfo
from ..types import ChatRequest, ChatResponse, ToolCall

# ---- Dynamic import as Any so mypy doesn't enforce vendor overloads ----
try:
    import importlib as _importlib

    _openai_mod = _importlib.import_module("openai")
    openai: Any = _openai_mod  # module or client typed as Any
    _HAS_OPENAI = True
except Exception:
    openai = None  # still fine because var is typed as Any
    _HAS_OPENAI = False


@dataclass
class OpenAIProvider(LLMProvider):
    api_key: Optional[str] = None
    _name: str = "openai"
    _default_model: str = "gpt-4.1-mini"

    @property
    def name(self) -> str:
        return self._name

    def list_models(self) -> list[ModelInfo]:
        return [
            ModelInfo("gpt-4.1-mini", "gpt-4.1", 128_000, True, True, True),
            ModelInfo("o4-mini", "o4", 200_000, True, True, True),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        # Mock path (SDK not present)
        if not _HAS_OPENAI:
            mock_text = "(mock openai) " + (
                req.messages[-1].content if req.messages else ""
            )
            return ChatResponse(
                content=mock_text,
                model=req.model or self._default_model,
                provider=self.name,
            )

        # Real path (keep everything as Any to satisfy mypy)
        client: Any = openai
        if self.api_key:
            try:
                client.api_key = self.api_key
            except Exception:
                pass

        tools_payload: Any = None
        if req.tools:
            tools_payload = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                }
                for t in req.tools
            ]

        start = time.time()
        completion: Any = cast(Any, client.chat.completions).create(
            model=req.model or self._default_model,
            messages=cast(Any, [m.__dict__ for m in req.messages]),
            temperature=req.temperature,
            max_tokens=req.max_tokens,
            tools=tools_payload,
            tool_choice=req.tool_choice if tools_payload is not None else "none",
            response_format={"type": "json_object"}
            if req.response_format == "json"
            else None,
            stream=False,
        )

        choice: Any = completion.choices[0]
        message_text: str = choice.message.content or ""  # renamed from `content`
        tool_calls: Optional[List[ToolCall]] = None

        tc_list: Any = getattr(choice.message, "tool_calls", None)
        if tc_list:
            tool_calls = []
            for tc in tc_list:
                args = tc.function.arguments
                if isinstance(args, str):
                    import json

                    try:
                        arguments = json.loads(args)
                    except Exception:
                        arguments = {}
                else:
                    arguments = args
                tool_calls.append(
                    ToolCall(id=tc.id, name=tc.function.name, arguments=arguments)
                )
            message_text = ""

        latency = int((time.time() - start) * 1000)
        usage: Any = getattr(completion, "usage", None)

        return ChatResponse(
            content=message_text,
            tool_calls=tool_calls,
            model=getattr(completion, "model", req.model or self._default_model),
            provider=self.name,
            prompt_tokens=(usage.prompt_tokens if usage is not None else None),
            completion_tokens=(usage.completion_tokens if usage is not None else None),
            latency_ms=latency,
        )

    def embed(
        self, texts: Iterable[str], model: Optional[str] = None
    ) -> list[list[float]]:
        return [[0.0] * 1536 for _ in texts]

    def count_tokens(self, text: str, model: Optional[str] = None) -> int:
        return max(1, len(text) // 4)


def register(api_key: Optional[str] = None, *, as_name: str = "openai") -> None:
    prov = OpenAIProvider(api_key=api_key, _name=as_name)
    from ..provider import llms

    llms.register(prov)
