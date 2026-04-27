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
import json
from typing import Iterator

import pytest

from wintermute import WintermuteMCP as mcp_mod
from wintermute.core import RunStatus, TestCaseRun


@pytest.fixture()
def fresh_run() -> Iterator[str]:
    """Drop a fresh TestCaseRun into the MCP module's ObjectRegistry and
    yield its registered id. The registry is shared module state, so we
    clean up after the test to avoid cross-test leakage."""
    run = TestCaseRun(run_id="TC-EX:once", test_case_code="TC-EX")
    rid = mcp_mod.registry.store(run, "test_run", run.run_id, prefix="run")
    try:
        yield rid
    finally:
        mcp_mod.registry.delete(rid)


# ---------------------------------------------------------------------------
# add_note_to_test_run
# ---------------------------------------------------------------------------


def test_add_note_appends_with_newline(fresh_run: str) -> None:
    """First note replaces empty notes; second note is appended on a new line."""
    raw = asyncio.run(mcp_mod.add_note_to_test_run(fresh_run, "first observation"))
    payload = json.loads(raw)
    assert payload["run_id"] == "TC-EX:once"
    assert payload["notes_length"] == len("first observation")

    raw2 = asyncio.run(mcp_mod.add_note_to_test_run(fresh_run, "second"))
    payload2 = json.loads(raw2)
    assert payload2["notes_length"] > payload["notes_length"]

    run = mcp_mod.registry.get_typed(fresh_run, TestCaseRun)
    assert run is not None
    assert run.notes == "first observation\nsecond"


def test_add_note_unknown_run_returns_error() -> None:
    raw = asyncio.run(mcp_mod.add_note_to_test_run("run:nonexistent", "ignored"))
    payload = json.loads(raw)
    assert "error" in payload


def test_add_note_wrong_type_returns_error() -> None:
    """Passing the id of a non-TestCaseRun must NOT corrupt that object."""
    from wintermute.core import Operation

    op = Operation(operation_name="bystander")
    op_id = mcp_mod.registry.store(op, "operation", op.operation_name, prefix="op")
    try:
        raw = asyncio.run(mcp_mod.add_note_to_test_run(op_id, "should-fail"))
        payload = json.loads(raw)
        assert "error" in payload
        assert "TestCaseRun" in payload["error"]
    finally:
        mcp_mod.registry.delete(op_id)


# ---------------------------------------------------------------------------
# add_vulnerability_to_test_run
# ---------------------------------------------------------------------------


def test_add_vulnerability_attaches_to_findings(fresh_run: str) -> None:
    raw = asyncio.run(
        mcp_mod.add_vulnerability_to_test_run(
            fresh_run,
            title="Stack overflow in halt handler",
            cvss=8,
            description="Triggered via crafted JTAG halt command.",
        )
    )
    payload = json.loads(raw)
    assert payload["run_id"] == "TC-EX:once"
    assert payload["findings_count"] == 1
    assert "vuln_id" in payload

    run = mcp_mod.registry.get_typed(fresh_run, TestCaseRun)
    assert run is not None
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.title == "Stack overflow in halt handler"
    assert finding.cvss == 8
    assert finding.description == "Triggered via crafted JTAG halt command."
    assert finding.vuln_id == payload["vuln_id"]


def test_add_vulnerability_default_description(fresh_run: str) -> None:
    asyncio.run(
        mcp_mod.add_vulnerability_to_test_run(
            fresh_run, title="Drive-by overflow", cvss=5
        )
    )
    run = mcp_mod.registry.get_typed(fresh_run, TestCaseRun)
    assert run is not None
    assert run.findings[0].description == ""


def test_add_vulnerability_unknown_run_returns_error() -> None:
    raw = asyncio.run(
        mcp_mod.add_vulnerability_to_test_run("run:nonexistent", title="x", cvss=1)
    )
    payload = json.loads(raw)
    assert "error" in payload


def test_add_vulnerability_accumulates(fresh_run: str) -> None:
    """Multiple vulns on the same run accumulate without overwriting."""
    asyncio.run(
        mcp_mod.add_vulnerability_to_test_run(fresh_run, title="vuln-1", cvss=3)
    )
    asyncio.run(
        mcp_mod.add_vulnerability_to_test_run(fresh_run, title="vuln-2", cvss=4)
    )
    run = mcp_mod.registry.get_typed(fresh_run, TestCaseRun)
    assert run is not None
    assert [v.title for v in run.findings] == ["vuln-1", "vuln-2"]


# ---------------------------------------------------------------------------
# Tools are MCP-bound (visible to external clients)
# ---------------------------------------------------------------------------


def test_new_tools_are_bound_to_fastmcp() -> None:
    """The two new endpoints must register on the FastMCP surface so MCP
    clients can discover them via list_tools."""
    bound_names = set(mcp_mod.mcp._tool_manager._tools.keys())
    assert "add_note_to_test_run" in bound_names
    assert "add_vulnerability_to_test_run" in bound_names


def test_status_update_still_works_alongside_new_tools(
    fresh_run: str,
) -> None:
    """Smoke check: the existing update_test_run_status is not affected by
    the new tools (regression)."""
    asyncio.run(mcp_mod.update_test_run_status(fresh_run, "in_progress"))
    run = mcp_mod.registry.get_typed(fresh_run, TestCaseRun)
    assert run is not None
    assert run.status == RunStatus.in_progress
    assert run.started_at is not None
