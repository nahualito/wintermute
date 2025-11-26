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

import json
import time
from dataclasses import dataclass
from typing import Any, Iterable, Literal, Optional

import boto3

from ..provider import LLMProvider, ModelInfo
from ..types import ChatRequest, ChatResponse, Message


def _as_bedrock_messages(msgs: list[Message]) -> list[dict[str, object]]:
    # Claude Messages API via Bedrock: roles are "user" or "assistant".
    out: list[dict[str, object]] = []
    for m in msgs:
        role = "assistant" if m.role == "assistant" else "user"  # map system->user
        out.append({"role": role, "content": [{"type": "text", "text": m.content}]})
    return out


_ModelFamily = Literal["anthropic", "deepseek", "llama", "other"]


def _detect_family(model_id: str) -> _ModelFamily:
    mid = model_id.lower()
    if "anthropic" in mid or "claude" in mid:
        return "anthropic"
    if mid.startswith("us.deepseek.") or "deepseek" in mid:
        return "deepseek"
    if "llama" in mid or "meta.llama" in mid or "llama3" in mid:
        return "llama"
    return "other"


@dataclass
class BedrockProvider(LLMProvider):
    """Amazon Bedrock LLM Provider.

    Example Bedrock models include Anthropic Claude, DeepSeek-R1, and Meta Llama.

    Example:
        >>> from wintermute.ai.providers.bedrock_provider import BedrockProvider
        >>> bedrock = BedrockProvider(region="us-east-1")
        >>> response = bedrock.chat(ChatRequest(...))

    Attributes:
        region (str): AWS region where Bedrock is available.
        default_model (str): Default model ID to use if none specified.
    """

    region: str = "us-east-1"
    # Make sure this is enabled for your account/region
    default_model: str = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    _name: str = "bedrock"

    @property
    def name(self) -> str:
        return self._name

    def list_models(self) -> list[ModelInfo]:
        # Include one Anthropic (Claude), one DeepSeek (inference profile), one Llama
        return [
            ModelInfo(
                name="anthropic.claude-3-5-sonnet-20240620-v1:0",
                family="claude-3-5",
                context_window=200_000,
                supports_tools=False,
                supports_json=True,
                supports_stream=True,
            ),
            # DeepSeek is invoked via an **inference profile** (note the 'us.' prefix)
            ModelInfo(
                name="us.deepseek.r1-v1:0",
                family="deepseek-r1",
                context_window=200_000,
                supports_tools=False,
                supports_json=True,
                supports_stream=True,
            ),
            # Example Llama model ID (ensure access in your region)
            ModelInfo(
                name="meta.llama3-8b-instruct-v1:0",
                family="llama3",
                context_window=128_000,
                supports_tools=False,
                supports_json=True,
                supports_stream=True,
            ),
        ]

    def chat(self, req: ChatRequest) -> ChatResponse:
        client: Any = boto3.client("bedrock-runtime", region_name=self.region)
        model_id = req.model or self.default_model
        family = _detect_family(model_id)

        # ----- Build body per model family (keys must match AWS docs) -----
        if family == "anthropic":
            # Claude via Messages API
            body_obj: dict[str, Any] = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": _as_bedrock_messages(req.messages),
                "temperature": float(req.temperature),
                "max_tokens": req.max_tokens if req.max_tokens is not None else 1024,
            }
        elif family == "deepseek":
            # DeepSeek-R1: text completion schema
            # https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-deepseek.html
            prompt = req.messages[-1].content if req.messages else ""
            body_obj = {
                "prompt": prompt,
                "temperature": float(req.temperature),
                "top_p": 0.9,
                "max_tokens": req.max_tokens if req.max_tokens is not None else 1024,
                # "stop": []  # optional list of strings
            }
        elif family == "llama":
            # Meta Llama Instruct: prompt + max_gen_len (NO max_tokens)
            # https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-meta.html
            user_text = req.messages[-1].content if req.messages else ""
            # Llama works best when wrapped in its header format; not strictly required but recommended.
            prompt = (
                "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n"
                f"{user_text}\n"
                "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
            )
            body_obj = {
                "prompt": prompt,
                "temperature": float(req.temperature),
                "top_p": 0.9,
                "max_gen_len": req.max_tokens if req.max_tokens is not None else 512,
            }
        else:
            # Generic fallback: simple prompt-only schema that many providers accept
            prompt = req.messages[-1].content if req.messages else ""
            body_obj = {
                "prompt": prompt,
                "temperature": float(req.temperature),
                "top_p": 0.9,
                "max_tokens": req.max_tokens if req.max_tokens is not None else 512,
            }

        body_bytes = json.dumps(body_obj).encode("utf-8")

        # ----- Invoke -----
        start = time.time()
        try:
            resp = client.invoke_model(
                modelId=model_id,
                body=body_bytes,
                contentType="application/json",
                accept="application/json",
            )
        except Exception as e:
            raise RuntimeError(
                f"Bedrock invoke_model failed: {e}\nRequest body: {json.dumps(body_obj)}"
            ) from e

        payload = resp["body"].read().decode("utf-8")
        j: Any = json.loads(payload)

        # ----- Parse response by family -----
        text = ""
        usage: dict[Any, Any] = {}
        if family == "anthropic":
            # Claude Messages: { "content": [ {"text": "..."} ], "usage": {...} }
            parts = j.get("content") or []
            if isinstance(parts, list) and parts and isinstance(parts[0], dict):
                text = str(parts[0].get("text", ""))
            usage = j.get("usage", {}) if isinstance(j.get("usage", {}), dict) else {}
        elif family == "deepseek":
            # DeepSeek: { "choices": [ { "text": "...", "stop_reason": "..." } ] }
            choices = j.get("choices") or []
            if isinstance(choices, list) and choices:
                text = str(choices[0].get("text", ""))
            # usage may be absent
        elif family == "llama":
            # Llama 3/3.1/3.2/4 Instruct can return various shapes; primary is "generation"
            if "generation" in j:
                text = str(j.get("generation", ""))
            elif "outputs" in j and isinstance(j["outputs"], list) and j["outputs"]:
                text = str(j["outputs"][0].get("text", ""))
            elif "choices" in j and isinstance(j["choices"], list) and j["choices"]:
                text = str(j["choices"][0].get("text", ""))
            elif "text" in j:
                text = str(j.get("text", ""))
            # usage fields differ; omit unless clearly present
        else:
            # Fallbacks seen in the wild
            text = str(j.get("outputText", j.get("generation", j.get("text", ""))))

        latency = int((time.time() - start) * 1000)

        return ChatResponse(
            content=text,
            model=model_id,
            provider=self.name,
            prompt_tokens=usage.get("input_tokens")
            if isinstance(usage, dict)
            else None,
            completion_tokens=usage.get("output_tokens")
            if isinstance(usage, dict)
            else None,
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
