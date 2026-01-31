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

# -*- coding: utf-8 -*-
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional

import boto3
from botocore.exceptions import ClientError

from ..provider import LLMProvider, ModelInfo
from ..types import ChatRequest, ChatResponse, ToolCall, ToolSpec


def _convert_tools_to_converse_spec(tools: Iterable[ToolSpec]) -> List[dict[str, Any]]:
    """Converts Wintermute ToolSpecs to Bedrock Converse 'toolSpec' format."""
    return [
        {
            "toolSpec": {
                "name": t.name,
                "description": t.description,
                "inputSchema": {"json": t.input_schema},
            }
        }
        for t in tools
    ]


def _parse_converse_response(
    output_message: dict[str, Any],
) -> tuple[str, list[ToolCall]]:
    """Parses the unified Converse API response into content and tool calls."""
    content_blocks = output_message.get("content", [])
    text_parts = []
    tool_calls = []

    for block in content_blocks:
        if "text" in block:
            text_parts.append(block["text"])
        elif "toolUse" in block:
            t_use = block["toolUse"]
            tool_calls.append(
                ToolCall(
                    id=t_use["toolUseId"],
                    name=t_use["name"],
                    arguments=t_use["input"],
                )
            )

    return "".join(text_parts), tool_calls


@dataclass
class BedrockProvider(LLMProvider):
    """
    Amazon Bedrock LLM Provider using the unified Converse API.
    Supports Claude, Llama, Mistral, and Nova with a single code path.
    """

    region: str = "us-east-1"
    default_model: str = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    _name: str = "bedrock"

    @property
    def name(self) -> str:
        return self._name

    def list_models(self) -> list[ModelInfo]:
        # With Converse API, most modern models support tools.
        return [
            ModelInfo(
                name="anthropic.claude-3-5-sonnet-20240620-v1:0",
                family="claude-3-5",
                context_window=200_000,
                supports_tools=True,
                supports_json=True,
                supports_stream=True,
            ),
            ModelInfo(
                name="us.deepseek.r1-v1:0",  # Check availability in your region
                family="deepseek-r1",
                context_window=128_000,
                supports_tools=True,  # Converse tries to map this; might fallback if unsupported
                supports_json=True,
                supports_stream=True,
            ),
            ModelInfo(
                name="meta.llama3-1-70b-instruct-v1:0",
                family="llama3",
                context_window=128_000,
                supports_tools=True,
                supports_json=True,
                supports_stream=True,
            ),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        client = boto3.client("bedrock-runtime", region_name=self.region)
        model_id = req.model or self.default_model

        # 1. Separate System Prompts (Converse API requires this)
        system_prompts = []
        messages = []

        for m in req.messages:
            if m.role == "system":
                system_prompts.append({"text": m.content})
            else:
                # Map Wintermute roles to Bedrock Converse roles
                # User -> user, Assistant -> assistant, Tool -> user (with toolResult)
                role = "assistant" if m.role == "assistant" else "user"

                # Simple text content handling
                # (For robust tool result handling, Wintermute Message types would need
                #  to support 'tool_result' blocks. For now we treat them as text.)
                messages.append({"role": role, "content": [{"text": m.content}]})

        # 2. Configure Tools
        tool_config = None
        if req.tools:
            tool_config = {
                "tools": _convert_tools_to_converse_spec(req.tools),
                "toolChoice": (
                    {"auto": {}}
                    if req.tool_choice == "auto"
                    else {"any": {}}
                    if req.tool_choice == "required"
                    else {"auto": {}}  # Default
                ),
            }

        # 3. Call Bedrock Converse
        start = time.time()
        try:
            # Build arguments dictionary to handle optional params cleanly
            kwargs = {
                "modelId": model_id,
                "messages": messages,
                "inferenceConfig": {
                    "temperature": float(req.temperature),
                    "maxTokens": req.max_tokens or 1024,
                },
            }
            if system_prompts:
                kwargs["system"] = system_prompts
            if tool_config:
                kwargs["toolConfig"] = tool_config

            response = client.converse(**kwargs)

        except ClientError as e:
            raise RuntimeError(f"Bedrock Converse failed: {e}") from e

        # 4. Parse Response
        output_msg = response["output"]["message"]
        content_text, tool_calls = _parse_converse_response(output_msg)

        usage = response.get("usage", {})
        latency = int((time.time() - start) * 1000)

        return ChatResponse(
            content=content_text,
            tool_calls=tool_calls,
            model=model_id,
            provider=self.name,
            prompt_tokens=usage.get("inputTokens"),
            completion_tokens=usage.get("outputTokens"),
            latency_ms=latency,
        )

    def embed(
        self, texts: Iterable[str], model: Optional[str] = None
    ) -> list[list[float]]:
        # Stub
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
