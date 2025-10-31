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

# wintermute/ai/use.py
from __future__ import annotations

from typing import List, Literal, Optional

from .provider import Router
from .types import ChatRequest, ChatResponse, Message, ToolSpec


def simple_chat(
    router: Router,
    prompt: str,
    task_tag: str = "generic",
    *,
    model: Optional[str] = None,
) -> str:
    """Perform a simple chat interaction with the LLM via the router.

    Example:
        >>> from wintermute.ai.bootstrap import init_router
        >>> from wintermute.ai.use import simple_chat
        >>> router = init_router()
        >>> # Default (Claude)
        >>> print(simple_chat(router, "Summarize: UART vs JTAG risks"))
        Here's a summary comparing the risks of UART vs JTAG:

        UART (Universal Asynchronous Receiver/Transmitter):

        1. Lower security risk overall
        2. Limited access to system internals
        3. Typically only provides console access
        4. Can potentially expose sensitive information in debug output
        5. Easier to secure by disabling or removing headers

        JTAG (Joint Test Action Group):

        1. Higher security risk
        2. Provides deep access to system internals
        3. Allows for full control of the processor and memory
        4. Can be used to extract firmware, modify code, and bypass security measures
        5. More challenging to fully secure, often requires physical fuses or permanent disabling
        >>> # DeepSeek (inference profile)
        >>> print(
        ...     simple_chat(
        ...         router,
        ...         "Summarize UART vs JTAG risks in 3 bullets",
        ...         model="us.deepseek.r1-v1:0",
        ...     )
        ... )
        - **Access Level**: UART exposes a serial console for command-line interaction, risking unauthorized system
        access, while JTAG provides deeper hardware control, enabling memory/firmware manipulation and security bypass.
        - **Exploitation Barrier**: UART requires basic tools (e.g., USB-to-TTL) and minimal expertise, making it easier
        to exploit, whereas JTAG demands specialized tools and advanced knowledge, raising the entry barrier for attackers.
        - **Impact Severity**: UART compromises may lead to configuration changes or log leaks, but JTAG breaches can
        result in full system control, firmware extraction, or intellectual property theft, posing a critical threat.
        >>> # Llama
        >>> print(
        ...     simple_chat(
        ...         router,
        ...         "Summarize UART vs JTAG risks in a One-liner",
        ...         model="meta.llama3-8b-instruct-v1:0",
        ...     )
        ... )
        UART (Universal Asynchronous Receiver-Transmitter) and JTAG (Joint Test Action Group) are both debugging interfaces,
        but UART is a more vulnerable and risky option due to its ability to be easily accessed and manipulated by an attacker,
        whereas JTAG is a more secure option due to its complexity and limited accessibility, making it a better choice for
        debugging and testing purposes.

    Args:
        router (Router): The Router instance to use for selecting the provider.
        prompt (str): The user prompt to send to the LLM.
        task_tag (str): A tag to categorize the task (default is "generic").
        model (Optional[str]): An optional model name to use for the request.
    """
    req = ChatRequest(
        messages=[Message(role="user", content=prompt)], task_tag=task_tag, model=model
    )
    provider, chosen = router.choose(req)
    resp = provider.chat(chosen)
    return resp.content if resp.content else f"(tool_calls={resp.tool_calls})"


def tool_calling_chat(
    router: Router,
    messages: List[Message],
    tools: List[ToolSpec],
    *,
    tool_choice: Literal["auto", "none", "required"] = "auto",
    response_format: Literal["text", "json"] = "text",
    task_tag: str = "generic",
    model: Optional[str] = None,
) -> ChatResponse:
    req = ChatRequest(
        messages=messages,
        tools=tools,
        tool_choice=tool_choice,
        response_format=response_format,
        task_tag=task_tag,
        model=model,
    )
    provider, chosen = router.choose(req)
    return provider.chat(chosen)
