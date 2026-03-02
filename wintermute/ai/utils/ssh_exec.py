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
