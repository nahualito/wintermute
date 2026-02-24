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
__description__ = (
    "Neural routing via Amazon Bedrock (Claude, Llama, DeepSeek) using LiteLLM."
)

from ..provider import LLMProvider, ModelInfo
from ..types import ChatRequest, ChatResponse, ToolCall


@dataclass
class BedrockProvider(LLMProvider):
    """
    Amazon Bedrock LLM Provider using LiteLLM.
    Supports Claude, Llama, Mistral, and Nova.
    """

    region: str = "us-east-1"
    default_model: str = "bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0"
    _name: str = "bedrock"

    @property
    def name(self) -> str:
        return self._name

    def list_models(self) -> list[ModelInfo]:
        return [
            ModelInfo(
                name="bedrock/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                family="claude-3-5",
                context_window=200_000,
                supports_tools=True,
                supports_json=True,
                supports_stream=True,
            ),
            ModelInfo(
                name="bedrock/us.deepseek.r1-v1:0",
                family="deepseek-r1",
                context_window=128_000,
                supports_tools=True,
                supports_json=True,
                supports_stream=True,
            ),
            ModelInfo(
                name="bedrock/meta.llama3-1-70b-instruct-v1:0",
                family="llama3",
                context_window=128_000,
                supports_tools=True,
                supports_json=True,
                supports_stream=True,
            ),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        model_id = req.model or self.default_model

        # litellm expects bedrock/ prefix for models if not already present
        if not model_id.startswith("bedrock/"):
            model_id = f"bedrock/{model_id}"

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
                max_tokens=req.max_tokens or 1024,
                tools=tools_payload,
                tool_choice=req.tool_choice if tools_payload else None,
                aws_region_name=self.region,
            )

        except Exception as e:
            raise RuntimeError(f"LiteLLM Bedrock completion failed: {e}") from e

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
        return [[0.0] * 1024 for _ in texts]

    def count_tokens(self, text: str, model: Optional[str] = None) -> int:
        return max(1, len(text) // 4)


def register(
    region: str = "us-east-1",
    *,
    as_name: str = "bedrock",
    default_model: Optional[str] = None,
) -> None:
    prov = BedrockProvider(region=region, _name=as_name)
    if default_model:
        prov.default_model = default_model
    from ..provider import llms

    llms.register(prov)
