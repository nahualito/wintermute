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

import os
from typing import Any, Dict, cast

import paramiko

from wintermute.ai.json_types import JSONObject

from .tool_factory import register_tools

# Global Cache to keep SSH connections alive between tool calls
_SSH_CLIENTS: Dict[str, Any] = {}


def _get_client(hostname: str, username: str, key_path: str) -> Any:
    client_key = f"{username}@{hostname}"
    # Reuse connection if valid
    if client_key in _SSH_CLIENTS:
        client = _SSH_CLIENTS[client_key]
        if client.get_transport() and client.get_transport().is_active():
            return client

    # Otherwise connect
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, key_filename=key_path, timeout=10)
    _SSH_CLIENTS[client_key] = client
    return client


def run_command_handler(args: JSONObject) -> JSONObject:
    """Executes a command (e.g., 'tar -xvf tool.tgz')."""
    try:
        host = cast(str, args.get("host"))
        user = cast(str, args.get("username"))
        # Handle optional password safely
        password = cast(str, args.get("password")) if args.get("password") else ""

        client = _get_client(host, user, password)

        # For exec_command
        command = cast(str, args.get("command"))
        stdin, stdout, stderr = client.exec_command(command)
        return {
            "stdout": stdout.read().decode("utf-8", errors="ignore"),
            "stderr": stderr.read().decode("utf-8", errors="ignore"),
            "exit_code": stdout.channel.recv_exit_status(),
        }
    except Exception as e:
        return {"error": str(e)}


def upload_file_handler(args: JSONObject) -> JSONObject:
    """
    Uploads a LOCAL file (binary/tgz) to the REMOTE server.
    The 'local_path' comes from the RAG; the file must exist on your machine.
    """
    local_path = cast(str, args.get("local_path"))
    remote_path = cast(str, args.get("remote_path"))

    if not os.path.exists(local_path):
        return {
            "error": f"Local file not found: {local_path}. Check your tools directory."
        }

    try:
        host = cast(str, args.get("host"))
        user = cast(str, args.get("username"))
        # Handle optional password safely
        password = cast(str, args.get("password")) if args.get("password") else ""

        client = _get_client(host, user, password)
        sftp = client.open_sftp()

        # This handles binaries, TGZs, everything.
        sftp.put(local_path, remote_path)
        sftp.close()

        return {"result": f"Successfully uploaded {local_path} to {remote_path}"}
    except Exception as e:
        return {"error": str(e)}


# --- Tool Registration ---

register_tools([run_command_handler, upload_file_handler])
