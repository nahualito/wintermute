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

import asyncio
import io
import json
from pathlib import Path
from typing import Iterator

import pytest
from rich.console import Console

from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.core import Operation, RunStatus, TestCase, TestPlan
from wintermute.WintermuteConsole import WintermuteConsole

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def console() -> Iterator[WintermuteConsole]:
    c = WintermuteConsole()
    c.rich_console = Console(file=io.StringIO(), force_terminal=False, width=200)
    try:
        yield c
    finally:
        # Drop the AI tools we registered into the global registry so we
        # don't pollute later tests.
        for name in (
            "ai_list_test_runs",
            "ai_get_run_details",
            "ai_update_run_status",
            "ai_add_run_note",
        ):
            global_tool_registry.unregister(name)


def _stdout(c: WintermuteConsole) -> str:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    return buf.getvalue()


def _reset_stdout(c: WintermuteConsole) -> None:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    buf.truncate(0)
    buf.seek(0)


def _seed_test_plan(op: Operation) -> None:
    """Seed the operation with a single-test-case plan generating one run."""
    tc = TestCase(
        code="TC-100",
        name="JTAG Boundary Scan",
        description="Verify JTAG boundary scan integrity.",
    )
    plan = TestPlan(
        code="TP-DEMO",
        name="Demo Plan",
        description="A toy plan",
        test_cases=[tc],
    )
    op.addTestPlan(plan)
    op.generateTestRuns()


def _dispatch(c: WintermuteConsole, cmd: str, args: list[str]) -> bool:
    return asyncio.run(c._dispatch_main_commands(cmd, args))


# ---------------------------------------------------------------------------
# Phase 1 — testruns load / generate / list
# ---------------------------------------------------------------------------


def test_testruns_load_attaches_plan(
    console: WintermuteConsole, tmp_path: Path
) -> None:
    plan = TestPlan(
        code="TP-WRITE",
        name="Write demo",
        description="",
        test_cases=[
            TestCase(code="TC-W1", name="Demo case", description="x"),
        ],
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan.to_dict()))

    console.cmd_testruns(["load", str(plan_path)])
    out = _stdout(console)
    assert "Loaded test plan" in out
    assert any(p.code == "TP-WRITE" for p in console.active_operation.test_plans)


def test_testruns_load_missing_file(console: WintermuteConsole, tmp_path: Path) -> None:
    console.cmd_testruns(["load", str(tmp_path / "nope.json")])
    assert "File not found" in _stdout(console)


def test_testruns_load_invalid_json(console: WintermuteConsole, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    console.cmd_testruns(["load", str(bad)])
    assert "Failed to parse" in _stdout(console)


def test_testruns_generate_creates_runs(
    console: WintermuteConsole,
) -> None:
    op = console.active_operation
    op.addTestPlan(
        TestPlan(
            code="TP-G",
            name="Gen",
            description="",
            test_cases=[TestCase(code="TC-G1", name="t", description="")],
        )
    )
    console.cmd_testruns(["generate"])
    out = _stdout(console)
    assert "Generated" in out
    assert any(r.run_id == "TC-G1:once" for r in op.test_runs)


def test_testruns_list_renders_table(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    _reset_stdout(console)
    console.cmd_testruns(["list"])
    out = _stdout(console)
    assert "Test Runs" in out
    assert "TC-100:once" in out
    assert "not_run" in out


def test_testruns_list_warns_when_empty(console: WintermuteConsole) -> None:
    console.cmd_testruns(["list"])
    out = _stdout(console)
    assert "No test runs yet" in out


# ---------------------------------------------------------------------------
# Phase 1 — Deep context [testruns/<run_id>]
# ---------------------------------------------------------------------------


def test_dispatch_testruns_sets_context(console: WintermuteConsole) -> None:
    asyncio.run(console._dispatch_main_commands("testruns", ["list"]))
    assert console.current_context == "testruns"


def test_typing_run_id_in_testruns_drills_in(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns"

    handled = _dispatch(console, "TC-100:once", [])
    assert handled is True
    assert console.current_context == "testruns/TC-100:once"


def test_typing_unknown_id_does_not_drill(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns"
    handled = _dispatch(console, "NOPE:once", [])
    assert handled is False
    assert console.current_context == "testruns"


def test_deep_context_show_renders_panel(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"
    handled = _dispatch(console, "show", [])
    assert handled is True
    out = _stdout(console)
    assert "TC-100:once" in out
    assert "JTAG Boundary Scan" in out
    assert "not_run" in out


def test_deep_context_status_updates_run(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"
    _dispatch(console, "status", ["passed"])
    run = console._find_test_run("TC-100:once")
    assert run is not None
    assert run.status == RunStatus.passed
    assert run.ended_at is not None


def test_deep_context_status_invalid(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"
    _dispatch(console, "status", ["bogus"])
    out = _stdout(console)
    assert "Invalid status" in out


def test_deep_context_start_pass_fail_shorthands(
    console: WintermuteConsole,
) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"

    # Re-fetch after each mutation to keep mypy from narrowing
    # ``run.status`` to a single Literal value.
    _dispatch(console, "start", [])
    after_start = console._find_test_run("TC-100:once")
    assert after_start is not None
    assert after_start.status == RunStatus.in_progress
    assert after_start.started_at is not None

    _dispatch(console, "pass", [])
    after_pass = console._find_test_run("TC-100:once")
    assert after_pass is not None
    assert after_pass.status == RunStatus.passed
    assert after_pass.ended_at is not None

    _dispatch(console, "fail", [])
    after_fail = console._find_test_run("TC-100:once")
    assert after_fail is not None
    assert after_fail.status == RunStatus.failed


def test_deep_context_note_appends(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"
    _dispatch(console, "note", ['"first', 'observation"'])
    _dispatch(console, "note", ['"second', 'line"'])
    run = console._find_test_run("TC-100:once")
    assert run is not None
    # Quoted multi-word notes must survive shlex parsing AND newlines.
    assert "first observation" in run.notes
    assert "second line" in run.notes
    assert run.notes.count("\n") == 1


def test_deep_context_vuln_appends(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"
    _dispatch(console, "vuln", ['"Stack', 'overflow"', "8"])
    run = console._find_test_run("TC-100:once")
    assert run is not None
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.title == "Stack overflow"
    assert finding.cvss == 8


def test_deep_context_vuln_invalid_cvss(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.current_context = "testruns/TC-100:once"
    _dispatch(console, "vuln", ['"x"', "high"])
    out = _stdout(console)
    assert "CVSS must be an integer" in out


def test_back_pops_deep_to_parent(console: WintermuteConsole) -> None:
    console.current_context = "testruns/TC-100:once"
    console.cmd_back()
    assert console.current_context == "testruns"


def test_back_pops_testruns_to_root(console: WintermuteConsole) -> None:
    console.current_context = "testruns"
    console.cmd_back()
    assert console.current_context == ""


def test_help_main_menu_lists_testruns(console: WintermuteConsole) -> None:
    console.cmd_help([])
    assert "testruns" in _stdout(console)


def test_help_testruns_subhelp_documents_deep_context(
    console: WintermuteConsole,
) -> None:
    console.cmd_help(["testruns"])
    out = _stdout(console)
    assert "testruns load" in out
    assert "testruns generate" in out
    assert "Deep Context" in out
    for token in ("show", "status", "start", "pass", "fail", "note", "vuln"):
        assert token in out


def test_help_in_deep_context_shows_testruns_subhelp(
    console: WintermuteConsole,
) -> None:
    console.current_context = "testruns/TC-100:once"
    console.cmd_help([])
    out = _stdout(console)
    assert "testruns load" in out
    assert "Deep Context" in out


# ---------------------------------------------------------------------------
# Phase 2 — Local AI tools registered with the global registry
# ---------------------------------------------------------------------------


def test_ai_tools_registered_at_init(console: WintermuteConsole) -> None:
    for name in (
        "ai_list_test_runs",
        "ai_get_run_details",
        "ai_update_run_status",
        "ai_add_run_note",
    ):
        assert name in global_tool_registry._tools


def test_ai_list_test_runs_returns_summaries(
    console: WintermuteConsole,
) -> None:
    _seed_test_plan(console.active_operation)
    result = console.ai_list_test_runs()
    assert result["total"] == 1
    assert result["runs"][0]["run_id"] == "TC-100:once"
    assert result["runs"][0]["status"] == "not_run"


def test_ai_get_run_details_includes_test_case(
    console: WintermuteConsole,
) -> None:
    _seed_test_plan(console.active_operation)
    result = console.ai_get_run_details("TC-100:once")
    assert result["run_id"] == "TC-100:once"
    assert result["test_case"]["name"] == "JTAG Boundary Scan"


def test_ai_get_run_details_unknown(console: WintermuteConsole) -> None:
    result = console.ai_get_run_details("NOPE")
    assert "error" in result


def test_ai_update_run_status_drives_finish(
    console: WintermuteConsole,
) -> None:
    _seed_test_plan(console.active_operation)
    result = console.ai_update_run_status("TC-100:once", "passed")
    assert result == {"run_id": "TC-100:once", "status": "passed"}
    run = console._find_test_run("TC-100:once")
    assert run is not None
    assert run.status == RunStatus.passed
    assert run.ended_at is not None


def test_ai_update_run_status_rejects_invalid(
    console: WintermuteConsole,
) -> None:
    _seed_test_plan(console.active_operation)
    result = console.ai_update_run_status("TC-100:once", "bogus")
    assert "error" in result
    assert "valid" in result


def test_ai_add_run_note_appends(console: WintermuteConsole) -> None:
    _seed_test_plan(console.active_operation)
    console.ai_add_run_note("TC-100:once", "from-ai")
    console.ai_add_run_note("TC-100:once", "second note")
    run = console._find_test_run("TC-100:once")
    assert run is not None
    assert "from-ai" in run.notes
    assert "second note" in run.notes
    assert run.notes.count("\n") == 1


def test_ai_tools_track_active_operation_swap(
    console: WintermuteConsole,
) -> None:
    """ai_list_test_runs reads from the live ``active_operation`` so
    `workspace switch` (which reassigns ``self.operation``) doesn't strand
    the AI on a stale reference."""
    _seed_test_plan(console.active_operation)
    assert console.ai_list_test_runs()["total"] == 1
    console.operation = Operation(operation_name="fresh")
    assert console.ai_list_test_runs()["total"] == 0


# ---------------------------------------------------------------------------
# Safeties — `back`, `help`, `show` still bypass contextual routing
# ---------------------------------------------------------------------------


def test_show_bypasses_contextual_routing_in_testruns(
    console: WintermuteConsole,
) -> None:
    """`show` must reach the operation tree handler, not the testruns list."""
    console.current_context = "testruns"
    handled = _dispatch(console, "show", [])
    assert handled is True
    out = _stdout(console)
    # Empty operation → tree handler emits the warning sentinel.
    assert "Operation is currently empty" in out
    assert "Test Runs" not in out
