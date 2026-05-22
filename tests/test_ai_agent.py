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

"""Phase 2 tests for the file-driven WorkerAgent.

These tests cover:

* Frontmatter parsing and profile loading from a temp directory.
* Implementation loading (relative against the configured dir, and
  absolute paths).
* The isolated tool registry — global registry contamination must not
  leak into the agent's surface.
* The autonomous tool-calling loop, including the two architectural
  rules called out in ``AGENT_REFACTOR_PLAN.md``:
    - ``object.__setattr__`` is used to attach ``tool_calls`` to the
      frozen ``Message`` dataclass.
    - ``tool_calls[*].function.arguments`` in the history is a JSON
      *string*, while the local handler receives the parsed dict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from wintermute.ai.agent import WorkerAgent, _parse_frontmatter
from wintermute.ai.json_types import JSONObject
from wintermute.ai.tools_runtime import Tool
from wintermute.ai.tools_runtime import tools as global_registry
from wintermute.ai.types import ChatResponse, ToolCall

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _RequestSnapshot:
    """Frozen-at-call-time copy of a ChatRequest, so post-call appends to
    the agent's mutable ``messages`` list cannot retroactively change what
    the assertions see.
    """

    def __init__(self, req: Any) -> None:
        self.messages = list(req.messages)
        self.tools = list(req.tools) if req.tools else None
        self.tool_choice = req.tool_choice
        self.model = req.model


def _make_router(responses: List[ChatResponse]) -> MagicMock:
    """Build a fake Router whose chosen provider returns ``responses`` in
    order, one per ``chat()`` call. The router records a snapshot of each
    ChatRequest on ``router.requests`` so tests can inspect the
    conversation history the agent built without aliasing the live list.
    """
    router = MagicMock()
    provider = MagicMock()
    router.requests = []
    iterator = iter(responses)

    def _chat(req: Any) -> ChatResponse:
        router.requests.append(_RequestSnapshot(req))
        return next(iterator)

    provider.chat.side_effect = _chat
    router.choose.side_effect = lambda req: (provider, req)
    return router


def _write_profile(directory: Path, name: str, body: str) -> Path:
    path = directory / f"{name}.md"
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Frontmatter parser
# ---------------------------------------------------------------------------


def test_parse_frontmatter_scalar_and_list() -> None:
    text = (
        "---\n"
        "name: jtag_specialist\n"
        "description: Talks to JTAG TAPs.\n"
        "tools:\n"
        "  - jtag_scan\n"
        "  - jtag_dump\n"
        "model: bedrock/anthropic.claude-3-sonnet\n"
        "---\n"
        "You are the JTAG specialist.\n"
    )
    meta, body = _parse_frontmatter(text)
    assert meta["name"] == "jtag_specialist"
    assert meta["description"] == "Talks to JTAG TAPs."
    assert meta["tools"] == ["jtag_scan", "jtag_dump"]
    assert meta["model"] == "bedrock/anthropic.claude-3-sonnet"
    assert body.strip() == "You are the JTAG specialist."


def test_parse_frontmatter_missing_fence_returns_body_only() -> None:
    text = "No frontmatter here, just text.\n"
    meta, body = _parse_frontmatter(text)
    assert meta == {}
    assert body == text


def test_parse_frontmatter_unterminated_returns_body_only() -> None:
    text = "---\nname: foo\nnever closed\n"
    meta, body = _parse_frontmatter(text)
    assert meta == {}
    assert body == text


# ---------------------------------------------------------------------------
# Profile / implementation loading
# ---------------------------------------------------------------------------


def test_load_profile_populates_state(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _write_profile(
        profiles,
        "tpm_verificator",
        (
            "---\n"
            "name: tpm_verificator\n"
            "description: TPM 2.0 attestation helper.\n"
            "tools:\n"
            "  - tpm_read_pcr\n"
            "  - tpm_quote\n"
            "---\n"
            "You verify TPM 2.0 quotes against expected PCR sets.\n"
        ),
    )
    agent = WorkerAgent(router=MagicMock(), profiles_dir=profiles)
    agent.load_profile("tpm_verificator")
    assert agent.name == "tpm_verificator"
    assert agent.description == "TPM 2.0 attestation helper."
    assert agent.allowed_tools == ["tpm_read_pcr", "tpm_quote"]
    assert "verify TPM 2.0 quotes" in agent.system_prompt
    assert agent.model is None


def test_load_profile_missing_raises(tmp_path: Path) -> None:
    agent = WorkerAgent(router=MagicMock(), profiles_dir=tmp_path)
    with pytest.raises(FileNotFoundError):
        agent.load_profile("does_not_exist")


def test_load_implementation_relative_path(tmp_path: Path) -> None:
    impls = tmp_path / "implementations"
    impls.mkdir()
    (impls / "task.md").write_text(
        "Step 1. Dump it. Step 2. Decrypt it.\n", encoding="utf-8"
    )
    agent = WorkerAgent(router=MagicMock(), implementations_dir=impls)
    agent.load_implementation("task.md")
    assert "Step 1" in agent.implementation
    assert "Step 2" in agent.implementation


def test_load_implementation_absolute_path(tmp_path: Path) -> None:
    f = tmp_path / "plan.md"
    f.write_text("absolute plan body", encoding="utf-8")
    agent = WorkerAgent(router=MagicMock(), implementations_dir=tmp_path / "ignored")
    agent.load_implementation(f)
    assert agent.implementation == "absolute plan body"


# ---------------------------------------------------------------------------
# Tool-registry isolation
# ---------------------------------------------------------------------------


def _make_tool(name: str) -> Tool:
    def handler(args: JSONObject) -> JSONObject:
        return {"echoed": args}

    return Tool(
        name=name,
        input_schema={"type": "object"},
        output_schema={},
        handler=handler,
        description=f"test tool {name}",
    )


def test_agent_registry_is_isolated_from_global() -> None:
    """Polluting the global registry must NOT show up in an agent."""
    sentinel = _make_tool("isolation_canary_global")
    global_registry.register(sentinel)
    try:
        agent = WorkerAgent(router=MagicMock())
        agent.allowed_tools = ["isolation_canary_global"]
        # The agent only sees its own registry — empty.
        assert agent.list_tools() == []
        assert agent._build_tool_specs() == []
    finally:
        global_registry.unregister("isolation_canary_global")


def test_agent_register_tool_is_local_only() -> None:
    """Registering a tool on an agent must NOT leak into the global registry
    or into another agent's registry."""
    agent_a = WorkerAgent(router=MagicMock())
    agent_b = WorkerAgent(router=MagicMock())
    local = _make_tool("local_to_agent_a")
    agent_a.register_tool(local)

    assert agent_a.list_tools() == ["local_to_agent_a"]
    assert agent_b.list_tools() == []
    assert "local_to_agent_a" not in global_registry._tools


# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_returns_immediately_when_no_tool_calls(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _write_profile(
        profiles,
        "talker",
        "---\nname: talker\ntools: []\n---\nYou just talk.\n",
    )
    impls = tmp_path / "impls"
    impls.mkdir()
    (impls / "say_hi.md").write_text("Say hi.", encoding="utf-8")

    router = _make_router([ChatResponse(content="hello operator")])
    agent = WorkerAgent(router=router, profiles_dir=profiles, implementations_dir=impls)
    agent.load_profile("talker")
    agent.load_implementation("say_hi.md")

    out = await agent.run()
    assert out == "hello operator"
    assert len(router.requests) == 1
    # Transcript: system + user + final assistant.
    assert [m.role for m in agent.transcript] == ["system", "user", "assistant"]


@pytest.mark.asyncio
async def test_run_executes_tool_call_then_returns(tmp_path: Path) -> None:
    """Cover the architectural critical-path: dataclass bypass + JSON split.

    The model first asks to call ``echo_tool`` with stringified arguments,
    then receives the tool output and produces a final answer.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _write_profile(
        profiles,
        "echo_agent",
        (
            "---\n"
            "name: echo_agent\n"
            "tools:\n"
            "  - echo_tool\n"
            "---\n"
            "Always echo what the user says.\n"
        ),
    )
    impls = tmp_path / "impls"
    impls.mkdir()
    (impls / "echo.md").write_text("Echo 'ping'.", encoding="utf-8")

    # Capture what the handler actually received so we can verify the
    # JSON split (string in history vs parsed dict to the handler).
    captured: dict[str, Any] = {}

    def handler(args: JSONObject) -> JSONObject:
        captured["args"] = dict(args)
        return {"output": "ping-from-tool"}

    tool = Tool(
        name="echo_tool",
        input_schema={"type": "object"},
        output_schema={},
        handler=handler,
        description="echoes",
    )

    first = ChatResponse(
        content="",
        tool_calls=[
            ToolCall(
                id="call_001",
                name="echo_tool",
                # Provider-shaped: arguments arrive as a JSON STRING (litellm style).
                arguments='{"msg": "ping"}',  # type: ignore[arg-type]
            )
        ],
    )
    final = ChatResponse(content="done — I echoed ping.")

    router = _make_router([first, final])
    agent = WorkerAgent(router=router, profiles_dir=profiles, implementations_dir=impls)
    agent.load_profile("echo_agent")
    agent.load_implementation("echo.md")
    agent.register_tool(tool)

    out = await agent.run()
    assert out == "done — I echoed ping."

    # Handler got the parsed dict.
    assert captured["args"] == {"msg": "ping"}

    # Second LLM request should carry the assistant turn with attached
    # tool_calls AND the tool-result message.
    second_req = router.requests[1]
    history_roles = [m.role for m in second_req.messages]
    assert history_roles == ["system", "user", "assistant", "tool"]

    assistant_msg = second_req.messages[2]
    # Dataclass-bypass: tool_calls must be present on the frozen Message.
    assert hasattr(assistant_msg, "tool_calls")
    tcalls = assistant_msg.tool_calls
    assert len(tcalls) == 1
    assert tcalls[0]["id"] == "call_001"
    # Argument-shape split: history carries a STRING, not a dict.
    assert isinstance(tcalls[0]["function"]["arguments"], str)
    assert tcalls[0]["function"]["arguments"] == '{"msg": "ping"}'

    tool_msg = second_req.messages[3]
    assert tool_msg.role == "tool"
    assert tool_msg.tool_call_id == "call_001"
    assert "ping-from-tool" in tool_msg.content


@pytest.mark.asyncio
async def test_run_stringifies_dict_arguments_in_history(tmp_path: Path) -> None:
    """Some providers return ``arguments`` already parsed as a dict — the
    history-side serialization must still produce a JSON string.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _write_profile(
        profiles,
        "dict_agent",
        "---\nname: dict_agent\ntools:\n  - noop\n---\nDo it.\n",
    )
    impls = tmp_path / "impls"
    impls.mkdir()
    (impls / "go.md").write_text("Go.", encoding="utf-8")

    def handler(args: JSONObject) -> JSONObject:
        return {"ok": True}

    tool = Tool(
        name="noop",
        input_schema={"type": "object"},
        output_schema={},
        handler=handler,
        description="noop",
    )

    first = ChatResponse(
        content="",
        tool_calls=[
            ToolCall(
                id="call_xyz",
                name="noop",
                arguments={"a": 1, "b": "two"},  # already-parsed dict
            )
        ],
    )
    final = ChatResponse(content="done")

    router = _make_router([first, final])
    agent = WorkerAgent(router=router, profiles_dir=profiles, implementations_dir=impls)
    agent.load_profile("dict_agent")
    agent.load_implementation("go.md")
    agent.register_tool(tool)

    await agent.run()
    second_req = router.requests[1]
    assistant_msg = second_req.messages[2]
    raw = assistant_msg.tool_calls[0]["function"]["arguments"]
    assert isinstance(raw, str)
    # JSON-round-trip equality (key order is irrelevant).
    import json as _json

    assert _json.loads(raw) == {"a": 1, "b": "two"}


@pytest.mark.asyncio
async def test_run_unknown_tool_returns_error_to_llm(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _write_profile(
        profiles,
        "x",
        "---\nname: x\ntools:\n  - missing\n---\nbody\n",
    )
    impls = tmp_path / "impls"
    impls.mkdir()
    (impls / "g.md").write_text("Go.", encoding="utf-8")

    first = ChatResponse(
        content="",
        tool_calls=[ToolCall(id="c1", name="missing", arguments="{}")],  # type: ignore[arg-type]
    )
    final = ChatResponse(content="gave up")
    router = _make_router([first, final])
    agent = WorkerAgent(router=router, profiles_dir=profiles, implementations_dir=impls)
    agent.load_profile("x")
    agent.load_implementation("g.md")
    # NOTE: we deliberately do NOT register "missing" — it's allowlisted
    # but absent from the local registry. The loop must surface an error
    # to the LLM rather than crashing.

    out = await agent.run()
    assert out == "gave up"
    tool_msg = router.requests[1].messages[3]
    assert "not registered" in tool_msg.content


@pytest.mark.asyncio
async def test_run_requires_profile_and_implementation() -> None:
    agent = WorkerAgent(router=MagicMock())
    with pytest.raises(RuntimeError, match="profile"):
        await agent.run()


@pytest.mark.asyncio
async def test_run_iteration_cap_bounds_runaway_loop(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _write_profile(profiles, "loop", "---\nname: loop\ntools:\n  - noop\n---\nbody\n")
    impls = tmp_path / "impls"
    impls.mkdir()
    (impls / "g.md").write_text("Go.", encoding="utf-8")

    def handler(args: JSONObject) -> JSONObject:
        return {"ok": True}

    tool = Tool(
        name="noop",
        input_schema={"type": "object"},
        output_schema={},
        handler=handler,
        description="noop",
    )
    # Every response asks for a tool call — the loop must never naturally exit.
    runaway = [
        ChatResponse(
            content="",
            tool_calls=[ToolCall(id=f"c{i}", name="noop", arguments="{}")],  # type: ignore[arg-type]
        )
        for i in range(50)
    ]
    router = _make_router(runaway)
    agent = WorkerAgent(
        router=router,
        profiles_dir=profiles,
        implementations_dir=impls,
        max_iterations=3,
    )
    agent.load_profile("loop")
    agent.load_implementation("g.md")
    agent.register_tool(tool)

    out = await agent.run()
    assert "Iteration cap reached" in out
    # Exactly max_iterations LLM calls before the cap fires.
    assert len(router.requests) == 3
