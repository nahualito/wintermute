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

import os
import uuid

import asyncssh

from wintermute.ai.json_types import JSONObject


def _build_connect_kwargs(
    target_alias: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> dict[str, object]:
    """Build the keyword arguments for ``asyncssh.connect()``.

    When a *password* is supplied the SSH agent and local key files are
    explicitly disabled so that asyncssh performs **pure password /
    keyboard-interactive authentication**.  This avoids two pitfalls:

    * ``client_keys=[]`` or ``client_keys=()`` are falsy / equal to the
      default sentinel, so asyncssh still scans ``~/.ssh/`` and attempts to
      decrypt passphrase-protected keys **using the password string** as
      the passphrase — which silently poisons the auth state.
    * A running SSH agent may offer keys that exhaust
      ``MaxAuthTries`` before password auth is attempted.

    Setting ``client_keys=None`` makes asyncssh assign
    ``self.client_keys = None`` (no keys loaded at all).

    When **no** password is given, all defaults are preserved so that
    ``~/.ssh/config``, the agent, and local keys work normally.
    """
    kwargs: dict[str, object] = {"host": target_alias, "known_hosts": None}
    if username:
        kwargs["username"] = username
    if password:
        kwargs["password"] = password
        # Prevent asyncssh from loading ~/.ssh/ keys or contacting the agent.
        # MUST be None — [] and () still trigger default key loading.
        kwargs["client_keys"] = None
        kwargs["agent_path"] = None
    if port is not None:
        kwargs["port"] = port
    return kwargs


class SSHSession:
    """Persistent SSH connection for multi-command workflows.

    Holds a single live ``asyncssh.SSHClientConnection`` that is opened via
    :meth:`connect` and closed via :meth:`close`.  Commands, background jobs,
    and SFTP transfers all reuse the same TCP connection.
    """

    def __init__(
        self,
        target_alias: str,
        username: str | None = None,
        password: str | None = None,
        port: int | None = None,
    ) -> None:
        self._connect_kwargs = _build_connect_kwargs(
            target_alias, username, password, port
        )
        self._conn: asyncssh.SSHClientConnection | None = None

    async def connect(self) -> None:
        """Open the persistent SSH connection."""
        self._conn = await asyncssh.connect(**self._connect_kwargs)

    async def close(self) -> None:
        """Close the persistent SSH connection."""
        if self._conn is not None:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None

    def _require_conn(self) -> asyncssh.SSHClientConnection:
        """Return the live connection or raise."""
        if self._conn is None:
            raise RuntimeError("SSHSession is not connected — call connect() first")
        return self._conn

    def is_connected(self) -> bool:
        """Return ``True`` if the underlying connection is still alive."""
        if self._conn is None:
            return False
        try:
            # Accessing the transport attribute probes connection liveness.
            transport = self._conn.get_extra_info("transport")
            return transport is not None
        except (asyncssh.Error, OSError):
            return False

    async def run(self, command: str) -> JSONObject:
        """Execute *command* on the persistent connection.

        Returns:
            ``{exit_code, stdout, stderr}``
        """
        conn = self._require_conn()
        try:
            result = await conn.run(command, check=False)
            exit_status: int = (
                result.exit_status if result.exit_status is not None else -1
            )
            return {
                "exit_code": exit_status,
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
            }
        except (asyncssh.Error, OSError) as e:
            return {"error": str(e)}

    async def run_background(self, command: str) -> str:
        """Launch *command* in the background via ``nohup``.

        The remote process writes its exit code, stdout, and stderr to
        well-known files under ``/tmp/wm_job_<job_id>.*`` so that
        :meth:`poll_job` can retrieve results later.

        Returns:
            A short UUID4 ``job_id``.
        """
        conn = self._require_conn()
        job_id = uuid.uuid4().hex[:12]
        wrapped = (
            f"nohup sh -c '{command} "
            f">/tmp/wm_job_{job_id}.out "
            f"2>/tmp/wm_job_{job_id}.err; "
            f"echo $? >/tmp/wm_job_{job_id}.rc' &"
        )
        await conn.run(wrapped, check=False)
        return job_id

    async def poll_job(self, job_id: str) -> JSONObject:
        """Check whether a background job has finished.

        Returns:
            ``{status: "running"}`` while the job is in progress, or
            ``{status: "done"|"error", exit_code, stdout, stderr}`` once
            the rc sentinel file exists.
        """
        conn = self._require_conn()
        rc_check = await conn.run(
            f"cat /tmp/wm_job_{job_id}.rc 2>/dev/null", check=False
        )
        rc_text = (rc_check.stdout or "").strip()
        if not rc_text:
            return {"status": "running"}

        stdout_res = await conn.run(
            f"cat /tmp/wm_job_{job_id}.out 2>/dev/null", check=False
        )
        stderr_res = await conn.run(
            f"cat /tmp/wm_job_{job_id}.err 2>/dev/null", check=False
        )
        exit_code = int(rc_text)
        status = "done" if exit_code == 0 else "error"
        return {
            "status": status,
            "exit_code": exit_code,
            "stdout": stdout_res.stdout or "",
            "stderr": stderr_res.stdout or "",
        }

    async def upload(self, local_path: str, remote_path: str) -> JSONObject:
        """Upload a local file to the remote host via SFTP."""
        if not os.path.exists(local_path):
            return {
                "error": f"Local file not found: {local_path}. Check your tools directory."
            }
        conn = self._require_conn()
        try:
            async with conn.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
            return {"result": f"Successfully uploaded {local_path} to {remote_path}"}
        except (asyncssh.Error, OSError) as e:
            return {"error": str(e)}

    async def download(self, remote_path: str, local_path: str) -> JSONObject:
        """Download a file from the remote host via SFTP."""
        conn = self._require_conn()
        try:
            async with conn.start_sftp_client() as sftp:
                await sftp.get(remote_path, local_path)
            return {"result": f"Successfully downloaded {remote_path} to {local_path}"}
        except (asyncssh.Error, OSError) as e:
            return {"error": str(e)}


async def run_command_async(
    target_alias: str,
    command: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> JSONObject:
    """Execute a command on a remote host via asyncssh.

    Leverages ``~/.ssh/config`` for host aliases, proxy jumps, and key
    management when *target_alias* matches a configured host entry.
    """
    kwargs = _build_connect_kwargs(target_alias, username, password, port)
    try:
        async with asyncssh.connect(**kwargs) as conn:
            result = await conn.run(command, check=False)
            exit_status: int = (
                result.exit_status if result.exit_status is not None else -1
            )
            if exit_status != 0:
                return {
                    "exit_code": exit_status,
                    "stderr": result.stderr or "",
                    "stdout": result.stdout or "",
                }
            return {
                "exit_code": 0,
                "stdout": result.stdout or "",
            }
    except (asyncssh.Error, OSError) as e:
        return {"error": str(e)}


async def upload_file_async(
    target_alias: str,
    local_path: str,
    remote_path: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> JSONObject:
    """Upload a local file to a remote host via SFTP over asyncssh.

    Leverages ``~/.ssh/config`` for host aliases, proxy jumps, and key
    management when *target_alias* matches a configured host entry.
    """
    if not os.path.exists(local_path):
        return {
            "error": f"Local file not found: {local_path}. Check your tools directory."
        }

    kwargs = _build_connect_kwargs(target_alias, username, password, port)
    try:
        async with asyncssh.connect(**kwargs) as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
        return {"result": f"Successfully uploaded {local_path} to {remote_path}"}
    except (asyncssh.Error, OSError) as e:
        return {"error": str(e)}


async def download_file_async(
    target_alias: str,
    remote_path: str,
    local_path: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> JSONObject:
    """Download a file from a remote host via SFTP over asyncssh.

    Leverages ``~/.ssh/config`` for host aliases, proxy jumps, and key
    management when *target_alias* matches a configured host entry.
    """
    kwargs = _build_connect_kwargs(target_alias, username, password, port)
    try:
        async with asyncssh.connect(**kwargs) as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.get(remote_path, local_path)
        return {"result": f"Successfully downloaded {remote_path} to {local_path}"}
    except (asyncssh.Error, OSError) as e:
        return {"error": str(e)}
