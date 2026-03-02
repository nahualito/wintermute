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
from typing import Iterable, Optional

import litellm

__category__ = "AI Models"
__description__ = "Inference routing via Groq Cloud (Llama, Mixtral) using LiteLLM."

from ..provider import LLMProvider, ModelInfo
from ..types import ChatRequest, ChatResponse, ToolCall


@dataclass
class GroqProvider(LLMProvider):
    """Groq LLM Provider for Wintermute AI using LiteLLM."""

    api_key: Optional[str] = None
    _name: str = "groq"
    _default_model: str = "groq/llama-3.3-70b-versatile"

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Inference routing via Groq Cloud (Llama, Mixtral). No specialized RAG knowledge."

    def list_models(self) -> list[ModelInfo]:
        """List available Groq models."""
        return [
            ModelInfo(
                "groq/llama-3.3-70b-versatile", "llama-3.3", 128_000, True, True, True
            ),
            ModelInfo(
                "groq/llama-3.1-70b-versatile", "llama-3.1", 128_000, True, True, True
            ),
            ModelInfo(
                "groq/llama-3.1-8b-instant", "llama-3.1", 128_000, True, True, True
            ),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        """Send a chat completion request to Groq using LiteLLM."""
        model_id = req.model or self._default_model

        # litellm expects groq/ prefix for models if not already present
        if not model_id.startswith("groq/"):
            model_id = f"groq/{model_id}"

        messages = [m.__dict__ for m in req.messages]

        tools_payload = None
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
        try:
            response = litellm.completion(
                model=model_id,
                messages=messages,
                temperature=float(req.temperature),
                max_tokens=req.max_tokens,
                tools=tools_payload,
                tool_choice=req.tool_choice if tools_payload else None,
                api_key=self.api_key,
                response_format={"type": "json_object"}
                if req.response_format == "json"
                else None,
            )

        except Exception as e:
            raise RuntimeError(f"LiteLLM Groq completion failed: {e}") from e

        choice = response.choices[0]
        content_text = choice.message.content or ""
        tool_calls = []

        if hasattr(choice.message, "tool_calls") and choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                tool_calls.append(
                    ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=tc.function.arguments,
                    )
                )

        usage = getattr(response, "usage", {})
        latency = int((time.time() - start) * 1000)

        return ChatResponse(
            content=content_text,
            tool_calls=tool_calls,
            model=model_id,
            provider=self.name,
            prompt_tokens=getattr(usage, "prompt_tokens", 0),
            completion_tokens=getattr(usage, "completion_tokens", 0),
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
