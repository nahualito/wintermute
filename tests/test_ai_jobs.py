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

"""Phase 3 tests for the asyncio-backed AgentJobManager.

These use stub agents (objects exposing only ``.name`` and ``.run()``)
rather than full WorkerAgents, so the tests target the manager's
state-machine in isolation: spawn → running → completed/failed, plus
explicit cancellation via :meth:`AgentJobManager.kill_job` and
:meth:`AgentJobManager.shutdown`.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest

from wintermute.ai.agent import WorkerAgent
from wintermute.ai.jobs import AgentJobManager


class _StubAgent:
    """Minimal duck-type compatible with WorkerAgent for the manager.

    We bypass WorkerAgent's profile/implementation requirements so each
    test can express run-time behaviour declaratively.
    """

    def __init__(self, name: str = "stub", *, result: str = "ok", delay: float = 0.0):
        self.name = name
        self._result = result
        self._delay = delay

    async def run(self) -> str:
        if self._delay:
            await asyncio.sleep(self._delay)
        return self._result


class _FailingAgent:
    name = "failer"

    async def run(self) -> str:
        raise RuntimeError("kaboom")


class _BlockingAgent:
    """Agent that sleeps far longer than any test should ever wait, so
    we can be sure kill_job is what actually ends it."""

    name = "blocker"

    async def run(self) -> str:
        await asyncio.sleep(60)
        return "should never get here"


def _as_agent(stub: Any) -> WorkerAgent:
    """Cast a duck-typed stub to WorkerAgent for the type checker."""
    return cast(WorkerAgent, stub)


# ---------------------------------------------------------------------------
# spawn / get_status — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spawn_returns_id_and_starts_running() -> None:
    mgr = AgentJobManager()
    job_id = await mgr.spawn_job(_as_agent(_StubAgent(delay=0.05)))
    assert isinstance(job_id, str) and len(job_id) >= 8

    snap = await mgr.get_status(job_id)
    assert snap is not None
    assert snap["status"] == "running"
    assert snap["agent_name"] == "stub"
    assert snap["output_buffer"] == ""

    await mgr.shutdown()


@pytest.mark.asyncio
async def test_completed_job_records_output() -> None:
    mgr = AgentJobManager()
    job_id = await mgr.spawn_job(_as_agent(_StubAgent(result="final answer")))
    # Drain the task — wait for it to finish without polling-by-sleep.
    # IMPORTANT: extract the task ref under the lock, then await it
    # OUTSIDE the lock so _run_and_record can re-acquire the lock to
    # write its final status.
    task = mgr._jobs[job_id]["task"]
    await task

    snap = await mgr.get_status(job_id)
    assert snap is not None
    assert snap["status"] == "completed"
    assert snap["output_buffer"] == "final answer"
    assert snap["finished_at"] is not None
    assert snap["finished_at"] >= snap["started_at"]


@pytest.mark.asyncio
async def test_get_status_unknown_job() -> None:
    mgr = AgentJobManager()
    assert await mgr.get_status("does-not-exist") is None


@pytest.mark.asyncio
async def test_unique_job_ids() -> None:
    mgr = AgentJobManager()
    ids = set()
    for _ in range(10):
        ids.add(await mgr.spawn_job(_as_agent(_StubAgent())))
    assert len(ids) == 10
    await mgr.shutdown()


@pytest.mark.asyncio
async def test_list_jobs_reports_every_spawned_run() -> None:
    mgr = AgentJobManager()
    a = await mgr.spawn_job(_as_agent(_StubAgent(name="a")))
    b = await mgr.spawn_job(_as_agent(_StubAgent(name="b")))
    listed = await mgr.list_jobs()
    assert {j["job_id"] for j in listed} == {a, b}
    await mgr.shutdown()


# ---------------------------------------------------------------------------
# Failure path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_job_records_error() -> None:
    mgr = AgentJobManager()
    job_id = await mgr.spawn_job(_as_agent(_FailingAgent()))
    task = mgr._jobs[job_id]["task"]
    # Task itself completes normally — the exception is swallowed and
    # mapped into the status dict, so awaiting it must not raise.
    await task

    snap = await mgr.get_status(job_id)
    assert snap is not None
    assert snap["status"] == "failed"
    assert "RuntimeError" in snap["output_buffer"]
    assert "kaboom" in snap["output_buffer"]


# ---------------------------------------------------------------------------
# kill_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kill_job_cancels_running_agent() -> None:
    mgr = AgentJobManager()
    job_id = await mgr.spawn_job(_as_agent(_BlockingAgent()))
    # Yield the loop once so the task actually enters the sleep before kill.
    await asyncio.sleep(0)

    assert await mgr.kill_job(job_id) is True

    snap = await mgr.get_status(job_id)
    assert snap is not None
    assert snap["status"] == "failed"
    assert "Cancelled by kill_job" in snap["output_buffer"]


@pytest.mark.asyncio
async def test_kill_job_unknown_returns_false() -> None:
    mgr = AgentJobManager()
    assert await mgr.kill_job("nope") is False


@pytest.mark.asyncio
async def test_kill_job_already_completed_returns_false() -> None:
    mgr = AgentJobManager()
    job_id = await mgr.spawn_job(_as_agent(_StubAgent(result="quick")))
    task = mgr._jobs[job_id]["task"]
    await task  # let _run_and_record acquire the lock and finalize state
    # Already done — kill is a no-op.
    assert await mgr.kill_job(job_id) is False
    snap = await mgr.get_status(job_id)
    assert snap is not None
    assert snap["status"] == "completed"


# ---------------------------------------------------------------------------
# shutdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shutdown_cancels_all_running_jobs() -> None:
    mgr = AgentJobManager()
    a = await mgr.spawn_job(_as_agent(_BlockingAgent()))
    b = await mgr.spawn_job(_as_agent(_BlockingAgent()))
    await asyncio.sleep(0)

    await mgr.shutdown()

    for jid in (a, b):
        snap = await mgr.get_status(jid)
        assert snap is not None
        assert snap["status"] == "failed"
        assert "Cancelled by kill_job" in snap["output_buffer"]


@pytest.mark.asyncio
async def test_shutdown_with_no_jobs_is_noop() -> None:
    mgr = AgentJobManager()
    # Should complete instantly — no jobs to wait on.
    await asyncio.wait_for(mgr.shutdown(), timeout=1.0)
