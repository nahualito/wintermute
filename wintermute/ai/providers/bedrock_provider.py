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

from ..provider import LLMProvider, ModelInfo
from ..types import ChatRequest, ChatResponse, Message

# Bedrock SDK (boto3). Keep import optional for strict mypy.
try:
    import boto3
except Exception as e:
    raise ImportError(
        "BedrockProvider requires boto3. Install with `pip install boto3` "
        "and ensure AWS credentials are configured."
    ) from e


def _as_bedrock_messages(msgs: list[Message]) -> list[dict[str, object]]:
    # Claude Messages API format via Bedrock
    out: list[dict[str, object]] = []
    for m in msgs:
        role = "user" if m.role in ("system", "user") else "assistant"
        out.append({"role": role, "content": [{"type": "text", "text": m.content}]})
    return out


@dataclass
class BedrockProvider(LLMProvider):
    region: str = "us-east-1"
    # Default Claude model; change per your account access
    default_model: str = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    _name: str = "bedrock"

    @property
    def name(self) -> str:
        return self._name

    def list_models(self) -> list[ModelInfo]:
        return [
            ModelInfo(self.default_model, "claude-3-5", 200_000, False, True, True),
            # Add additional Bedrock models you’ve provisioned here
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        if boto3 is None:
            content = "(mock bedrock) " + (
                req.messages[-1].content if req.messages else ""
            )
            return ChatResponse(
                content=content,
                model=req.model or self.default_model,
                provider=self.name,
            )

        client = boto3.client("bedrock-runtime", region_name=self.region)
        model_id = req.model or self.default_model
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": _as_bedrock_messages(req.messages),
            "temperature": req.temperature,
            "max_tokens": req.max_tokens or 1024,
        }
        start = time.time()
        resp = client.invoke_model(
            modelId=model_id,
            body=bytes(str(body), "utf-8"),
            contentType="application/json",
            accept="application/json",
        )
        # Minimal parse: boto3 returns StreamingBody; we read it and eval json safely
        payload = resp["body"].read().decode("utf-8")
        # To avoid runtime deps here, rely on stdlib json
        import json

        j = json.loads(payload)
        # Claude Messages returns list of content blocks
        parts = j.get("content", [])
        text = ""
        if parts and isinstance(parts, list):
            first = parts[0]
            if isinstance(first, dict):
                text = str(first.get("text", ""))
        latency = int((time.time() - start) * 1000)
        return ChatResponse(
            content=text,
            model=model_id,
            provider=self.name,
            prompt_tokens=j.get("usage", {}).get("input_tokens"),
            completion_tokens=j.get("usage", {}).get("output_tokens"),
            latency_ms=latency,
        )

    def embed(
        self, texts: Iterable[str], model: Optional[str] = None
    ) -> list[list[float]]:
        # Stub: replace with Titan Embeddings or similar on Bedrock
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
        object.__setattr__(prov, "default_model", default_model)
    from ..provider import llms

    llms.register(prov)
