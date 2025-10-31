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

# ---- Dynamic import as Any ----
try:
    import importlib as _importlib

    _groq_mod = _importlib.import_module("groq")
    GroqClient: Any = getattr(_groq_mod, "Groq")
    _HAS_GROQ = True
except Exception:
    GroqClient = None  # typed as Any below
    _HAS_GROQ = False


@dataclass
class GroqProvider(LLMProvider):
    """Groq LLM Provider for Wintermute AI.

    Example:
        >>> from wintermute.ai import llms
        >>> from wintermute.ai.providers.groq_provider import GroqProvider, register
        >>> groq_prov = GroqProvider(api_key="your_groq_api_key")
        >>> llms.register(groq_prov)

    Note: Groq SDK must be installed separately with `pip install groq`.

    Attributes:
        api_key (Optional[str]): Groq API key for authentication.
    """

    api_key: Optional[str] = None
    _name: str = "groq"
    _default_model: str = "llama-3.1-8b-instant"

    @property
    def name(self) -> str:
        return self._name

    def list_models(self) -> list[ModelInfo]:
        """List available Groq models."""
        return [
            ModelInfo("llama-3.1-8b-instant", "llama-3.1", 128_000, True, True, True),
            ModelInfo(
                "llama-3.1-70b-versatile", "llama-3.1", 128_000, True, True, True
            ),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        """Send a chat completion request to Groq LLM.

        Args:
            req (ChatRequest): The chat request containing messages and parameters.
        Returns:
            ChatResponse: The response from the Groq LLM.
        """
        # Mock path (SDK not present)
        if not _HAS_GROQ:
            mock_text = "(mock groq) " + (
                req.messages[-1].content if req.messages else ""
            )
            return ChatResponse(
                content=mock_text,
                model=req.model or self._default_model,
                provider=self.name,
            )

        client: Any = GroqClient(api_key=self.api_key)

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


def register(api_key: Optional[str] = None, *, as_name: str = "groq") -> None:
    """Register the GroqProvider with Wintermute AI LLM registry."""
    prov = GroqProvider(api_key=api_key, _name=as_name)
    from ..provider import llms

    llms.register(prov)
