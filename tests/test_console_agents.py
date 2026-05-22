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

"""Phase 4 tests for the Supervisor REPL.

These verify:

* The supervisor exposes only its three exclusive native tools — global
  cartridge tools must NOT appear in the supervisor's surface.
* Each of the three supervisor tool dispatch paths
  (``generate_implementation_file``, ``spawn_agent``, ``check_agent_status``)
  produces the expected side effect / response.
* The supervisor loop wires LLM tool_calls into the dispatcher and then
  returns the final assistant content (intent routing end-to-end).
* The operator-facing ``ai agent status [job_id]`` command reads from the
  job manager.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, List, cast
from unittest.mock import MagicMock

import pytest
from rich.console import Console as RichConsole

from wintermute.ai.types import ChatResponse, ToolCall
from wintermute.WintermuteConsole import WintermuteConsole

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def console(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WintermuteConsole:
    """A WintermuteConsole with implementations dir + profiles dir
    redirected into tmp_path so the supervisor tools don't write to the
    operator's real ``~/.wintermute`` tree."""
    impls = tmp_path / "implementations"
    profiles = tmp_path / "profiles"
    impls.mkdir()
    profiles.mkdir()
    # Both the supervisor's generate_implementation_file dispatcher and
    # WorkerAgent.load_implementation read this module constant.
    monkeypatch.setattr(
        "wintermute.WintermuteConsole.DEFAULT_IMPLEMENTATIONS_DIR", impls
    )
    monkeypatch.setattr("wintermute.ai.agent.DEFAULT_IMPLEMENTATIONS_DIR", impls)
    monkeypatch.setattr("wintermute.ai.agent.DEFAULT_PROFILES_DIR", profiles)

    c = WintermuteConsole()
    c.rich_console = MagicMock()  # suppress prints
    return c


def _make_router_for_supervisor(responses: List[ChatResponse]) -> MagicMock:
    """Fake Router that returns ``responses`` in order from provider.chat()."""
    router = MagicMock()
    provider = MagicMock()
    router.default_model = "test-model"
    router.default_provider = "test"
    iterator = iter(responses)

    def _chat(req: Any) -> ChatResponse:
        router.last_request = req
        return next(iterator)

    provider.chat.side_effect = _chat
    router.choose.side_effect = lambda req: (provider, req)
    return router


# ---------------------------------------------------------------------------
# Tool surface isolation
# ---------------------------------------------------------------------------


def test_supervisor_exposes_only_three_native_tools(
    console: WintermuteConsole,
) -> None:
    specs = console._supervisor_tool_specs()
    names = {s.name for s in specs}
    assert names == {
        "generate_implementation_file",
        "spawn_agent",
        "check_agent_status",
    }


def test_supervisor_surface_does_not_include_global_tools(
    console: WintermuteConsole,
) -> None:
    """Even if the global registry has tools, the supervisor sees only
    its own three."""
    from wintermute.ai.tools_runtime import Tool
    from wintermute.ai.tools_runtime import tools as global_registry

    sentinel = Tool(
        name="cartridge_canary",
        input_schema={},
        output_schema={},
        handler=lambda args: {"ok": True},
        description="should never leak into the supervisor",
    )
    global_registry.register(sentinel)
    try:
        specs = console._supervisor_tool_specs()
        assert "cartridge_canary" not in {s.name for s in specs}
    finally:
        global_registry.unregister("cartridge_canary")


# ---------------------------------------------------------------------------
# Supervisor tool dispatcher
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_implementation_file_writes_to_disk(
    console: WintermuteConsole, tmp_path: Path
) -> None:
    out = await console._supervisor_dispatch(
        "generate_implementation_file",
        {"content": "Step 1. Dump.\nStep 2. Decrypt.", "filename": "task.md"},
    )
    result = json.loads(out)
    assert "path" in result
    written = Path(result["path"])
    assert written.is_file()
    assert "Dump" in written.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_generate_implementation_file_rejects_empty_filename(
    console: WintermuteConsole,
) -> None:
    out = await console._supervisor_dispatch(
        "generate_implementation_file",
        {"content": "x", "filename": "  "},
    )
    assert json.loads(out)["error"] == "filename is required"


@pytest.mark.asyncio
async def test_spawn_agent_returns_job_id_in_background_mode(
    console: WintermuteConsole, tmp_path: Path
) -> None:
    # Set up a real profile + implementation that load_profile will find.
    (tmp_path / "profiles" / "echo_agent.md").write_text(
        "---\nname: echo_agent\ntools: []\n---\nYou echo things.\n",
        encoding="utf-8",
    )
    (tmp_path / "implementations" / "echo.md").write_text(
        "Say hello.", encoding="utf-8"
    )
    # Stub the router so the spawned WorkerAgent's run() returns quickly
    # without making a real LLM call. The agent will immediately end the
    # loop (no tool calls).
    console.ai_router = _make_router_for_supervisor([ChatResponse(content="hi")])

    out = await console._supervisor_dispatch(
        "spawn_agent",
        {"profile": "echo_agent", "implementation_file": "echo.md"},
    )
    result = json.loads(out)
    assert result["mode"] == "background"
    assert isinstance(result["job_id"], str)
    assert result["agent_name"] == "echo_agent"

    # The job should be tracked by the manager.
    snap = await console.job_manager.get_status(result["job_id"])
    assert snap is not None
    assert snap["agent_name"] == "echo_agent"

    await console.job_manager.shutdown()


@pytest.mark.asyncio
async def test_spawn_agent_missing_profile_returns_error(
    console: WintermuteConsole,
) -> None:
    console.ai_router = MagicMock()
    out = await console._supervisor_dispatch(
        "spawn_agent",
        {"profile": "ghost", "implementation_file": "noop.md"},
    )
    assert "error" in json.loads(out)


@pytest.mark.asyncio
async def test_check_agent_status_unknown_job(console: WintermuteConsole) -> None:
    out = await console._supervisor_dispatch("check_agent_status", {"job_id": "nope"})
    assert "error" in json.loads(out)


# ---------------------------------------------------------------------------
# End-to-end supervisor loop (intent routing)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supervisor_loop_routes_tool_call_then_returns(
    console: WintermuteConsole,
) -> None:
    """The LLM asks for `generate_implementation_file`; the supervisor
    must execute it via the dispatcher and feed the result back. The
    second LLM turn returns final content with no tool_calls — the loop
    exits with that content.
    """
    first = ChatResponse(
        content="",
        tool_calls=[
            ToolCall(
                id="call_001",
                name="generate_implementation_file",
                arguments='{"content": "plan body", "filename": "plan.md"}',  # type: ignore[arg-type]
            )
        ],
    )
    final = ChatResponse(content="Plan written, see ~/.wintermute/agentic/...")
    console.ai_router = _make_router_for_supervisor([first, final])

    out = await console._run_supervisor("Plan an attack on the TPM.")
    assert out == "Plan written, see ~/.wintermute/agentic/..."

    # Side effect: the dispatcher actually wrote the file.
    written = list((console.SUPERVISOR_TOOL_SPECS,))  # silence unused-var lint
    del written
    # We can't easily reach the tmp_path here, so instead trust the
    # generate test above and check the second LLM request carried the
    # tool result message.
    second_req = console.ai_router.last_request
    roles = [m.role for m in second_req.messages]
    assert roles == ["system", "user", "assistant", "tool"]
    tool_msg = second_req.messages[3]
    assert tool_msg.tool_call_id == "call_001"
    payload = json.loads(tool_msg.content)
    assert "path" in payload


@pytest.mark.asyncio
async def test_supervisor_loop_returns_immediately_when_no_tool_calls(
    console: WintermuteConsole,
) -> None:
    console.ai_router = _make_router_for_supervisor(
        [ChatResponse(content="just a direct answer")]
    )
    out = await console._run_supervisor("what is JTAG?")
    assert out == "just a direct answer"


@pytest.mark.asyncio
async def test_supervisor_loop_iteration_cap(console: WintermuteConsole) -> None:
    """A pathological model that always calls a tool must be bounded."""
    runaway = [
        ChatResponse(
            content="",
            tool_calls=[
                ToolCall(
                    id=f"c{i}",
                    name="check_agent_status",
                    arguments='{"job_id": "nope"}',  # type: ignore[arg-type]
                )
            ],
        )
        for i in range(50)
    ]
    console.ai_router = _make_router_for_supervisor(runaway)
    out = await console._run_supervisor("loop forever")
    assert "Iteration cap reached" in out


@pytest.mark.asyncio
async def test_supervisor_loop_without_router_returns_marker(
    console: WintermuteConsole,
) -> None:
    console.ai_router = None
    out = await console._run_supervisor("anything")
    assert "AI router" in out


# ---------------------------------------------------------------------------
# Operator-facing `ai agent status` command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_ai_agent_status_unknown_job_id(
    console: WintermuteConsole,
) -> None:
    await console._cmd_ai_agent(["status", "bogus"])
    # Should have called rich_console.print with an unknown-job message.
    calls = cast(MagicMock, console.rich_console.print).call_args_list
    assert any("Unknown job_id" in str(c) for c in calls)


@pytest.mark.asyncio
async def test_cmd_ai_agent_status_lists_all_jobs(
    console: WintermuteConsole,
) -> None:
    class _StubAgent:
        name = "stub_a"

        async def run(self) -> str:
            await asyncio.sleep(60)  # long; we never wait for it
            return "never"

    # Swap in a recording rich console so we can read what was rendered.
    console.rich_console = RichConsole(record=True, width=120)

    job_id = await console.job_manager.spawn_job(_StubAgent())  # type: ignore[arg-type]
    try:
        await console._cmd_ai_agent(["status"])
        rendered = console.rich_console.export_text()
        assert job_id in rendered
        assert "stub_a" in rendered
    finally:
        await console.job_manager.shutdown()


@pytest.mark.asyncio
async def test_cmd_ai_agent_status_specific_job(console: WintermuteConsole) -> None:
    class _StubAgent:
        name = "stub_b"

        async def run(self) -> str:
            return "done!"

    console.rich_console = RichConsole(record=True, width=120)

    job_id = await console.job_manager.spawn_job(_StubAgent())  # type: ignore[arg-type]
    # Drain the task so its status flips to "completed".
    task = console.job_manager._jobs[job_id]["task"]
    await task

    await console._cmd_ai_agent(["status", job_id])
    rendered = console.rich_console.export_text()
    assert "completed" in rendered
    assert "done!" in rendered


@pytest.mark.asyncio
async def test_cmd_ai_agent_no_args_prints_usage(
    console: WintermuteConsole,
) -> None:
    await console._cmd_ai_agent([])
    calls = cast(MagicMock, console.rich_console.print).call_args_list
    rendered = " ".join(str(c) for c in calls)
    assert "Usage" in rendered
