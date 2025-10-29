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
from typing import Iterable, Optional, Protocol

from .types import ChatRequest, ChatResponse


@dataclass(frozen=True)
class ModelInfo:
    name: str
    family: str
    context_window: int
    supports_tools: bool
    supports_json: bool
    supports_stream: bool
    supports_vision: bool = False


class LLMProvider(Protocol):
    @property
    def name(self) -> str: ...
    def list_models(self) -> list[ModelInfo]: ...
    def chat(self, req: ChatRequest) -> ChatResponse: ...
    def embed(
        self, texts: Iterable[str], model: Optional[str] = None
    ) -> list[list[float]]: ...
    def count_tokens(self, text: str, model: Optional[str] = None) -> int: ...


class LLMRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, LLMProvider] = {}

    def register(self, provider: LLMProvider) -> None:
        self._providers[provider.name] = provider

    def get(self, name: str) -> LLMProvider:
        return self._providers[name]

    def providers(self) -> list[str]:
        return list(self._providers.keys())


llms = LLMRegistry()


class Router:
    """Pluggable routing policy. Default: stick to default provider/model."""

    def __init__(
        self, default_provider: str, default_model: Optional[str] = None
    ) -> None:
        self.default_provider = default_provider
        self.default_model = default_model

    def choose(self, req: ChatRequest) -> tuple[LLMProvider, ChatRequest]:
        provider = llms.get(self.default_provider)
        model = req.model or self.default_model
        # Example heuristic: cheap tasks
        if req.task_tag and "cheap" in req.task_tag:
            for p in llms.providers():
                if p.startswith("groq"):
                    provider = llms.get(p)
                    break
        new_req = ChatRequest(**{**req.__dict__, "model": model})
        return provider, new_req
