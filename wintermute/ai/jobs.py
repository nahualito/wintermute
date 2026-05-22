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

"""Background job management for long-running :class:`WorkerAgent` runs.

Phase 3 of ``AGENT_REFACTOR_PLAN.md``. Some agents — fuzzers, ROM
disassemblers, brute-forcers — take minutes to hours to complete. The
supervisor console needs to spawn these as background tasks, poll their
status, and kill them on demand, all without blocking the REPL.

The :class:`AgentJobManager` is a thin wrapper around :func:`asyncio.
create_task` that tracks the lifecycle of every spawned agent run. Each
job entry is exactly the shape the refactor plan specifies::

    {job_id: {"task": asyncio.Task, "status": "running|completed|failed",
              "output_buffer": str, ...}}

Status transitions:

* ``running``   — set immediately on spawn.
* ``completed`` — agent.run() returned normally; output_buffer holds the
  final assistant content.
* ``failed``    — agent.run() raised (including cancellation via
  :meth:`kill_job`); output_buffer holds the error message.

Only the three statuses called out in the plan are used; cancellation is
folded into ``failed`` and disambiguated through ``output_buffer``.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from .agent import WorkerAgent

log = logging.getLogger(__name__)


JobStatus = str  # "running" | "completed" | "failed"


class AgentJobManager:
    """Tracks background :class:`WorkerAgent` runs as asyncio tasks."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    # -- spawn ---------------------------------------------------------------

    async def spawn_job(self, agent: WorkerAgent) -> str:
        """Schedule ``agent.run()`` as a background task; return a job id.

        Returns immediately; the agent runs concurrently. Use
        :meth:`get_status` to poll completion and read the output buffer.
        """
        job_id = uuid.uuid4().hex[:12]
        task = asyncio.create_task(
            self._run_and_record(job_id, agent), name=f"agent-job-{job_id}"
        )
        async with self._lock:
            self._jobs[job_id] = {
                "task": task,
                "status": "running",
                "output_buffer": "",
                "agent_name": agent.name,
                "started_at": time.time(),
                "finished_at": None,
            }
        return job_id

    async def _run_and_record(self, job_id: str, agent: WorkerAgent) -> None:
        """Internal task body. Catches everything so the status dict is
        always populated, even on cancellation or hard failures.
        """
        try:
            output = await agent.run()
        except asyncio.CancelledError:
            async with self._lock:
                if job_id in self._jobs:
                    self._jobs[job_id]["status"] = "failed"
                    self._jobs[job_id]["output_buffer"] = (
                        "Cancelled by kill_job before completion."
                    )
                    self._jobs[job_id]["finished_at"] = time.time()
            # Re-raise so the Task object's state reflects cancellation
            # rather than being silently swallowed (callers awaiting the
            # task directly still see CancelledError).
            raise
        except Exception as exc:
            log.exception("Agent job %s raised", job_id)
            async with self._lock:
                if job_id in self._jobs:
                    self._jobs[job_id]["status"] = "failed"
                    self._jobs[job_id]["output_buffer"] = (
                        f"Agent raised {type(exc).__name__}: {exc}"
                    )
                    self._jobs[job_id]["finished_at"] = time.time()
            return
        async with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["status"] = "completed"
                self._jobs[job_id]["output_buffer"] = output
                self._jobs[job_id]["finished_at"] = time.time()

    # -- introspection -------------------------------------------------------

    async def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return a snapshot of the job, or ``None`` if unknown.

        The returned dict excludes the live :class:`asyncio.Task` handle so
        it is safe to serialize / pretty-print from the console.
        """
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return {
                "job_id": job_id,
                "status": job["status"],
                "agent_name": job.get("agent_name", ""),
                "output_buffer": job["output_buffer"],
                "started_at": job.get("started_at"),
                "finished_at": job.get("finished_at"),
            }

    async def list_jobs(self) -> List[Dict[str, Any]]:
        """Return a snapshot list of every tracked job."""
        async with self._lock:
            ids = list(self._jobs.keys())
        # Resolve each status outside the lock to avoid holding it across awaits.
        out: List[Dict[str, Any]] = []
        for jid in ids:
            snap = await self.get_status(jid)
            if snap is not None:
                out.append(snap)
        return out

    # -- termination ---------------------------------------------------------

    async def kill_job(self, job_id: str) -> bool:
        """Cancel a running job. Returns ``True`` iff cancellation was
        actually issued (job exists, was still running).

        After a successful kill the job's status will read ``"failed"``
        with ``output_buffer="Cancelled by kill_job before completion."``,
        per the status-set documented at module top.
        """
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            task: asyncio.Task[None] = job["task"]
            if task.done():
                return False
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            # _run_and_record already updated the job record; the
            # re-raised CancelledError lands here and is intentionally
            # swallowed because the caller wants the kill, not the trace.
            pass
        return True

    async def shutdown(self) -> None:
        """Cancel every running job and await their teardown.

        Called by the console on exit so we never leak background agents
        past the REPL's lifetime.
        """
        async with self._lock:
            running = [
                (jid, job["task"])
                for jid, job in self._jobs.items()
                if not job["task"].done()
            ]
        for _, task in running:
            task.cancel()
        if running:
            await asyncio.gather(*(t for _, t in running), return_exceptions=True)


__all__ = ["AgentJobManager", "JobStatus"]
