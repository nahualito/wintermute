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
import asyncio.subprocess
import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, List, Optional, cast

import anyio
import pytest

from wintermute.ai.types import ToolSpec
from wintermute.integrations import mcp_runtime
from wintermute.integrations.mcp_runtime import MCPClientManager

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class _FakeTool:
    name: str
    description: str
    inputSchema: dict[str, Any] = field(default_factory=dict)


@dataclass
class _FakeListing:
    tools: List[_FakeTool]


class _FakeStdoutReader:
    """Returns EOF immediately so the stdout pump exits cleanly."""

    async def read(self, n: int) -> bytes:
        return b""


class _FakeStdinWriter:
    def __init__(self) -> None:
        self.closed = False
        self.buffer: list[bytes] = []

    def write(self, data: bytes) -> None:
        if self.closed:
            raise BrokenPipeError("stdin closed")
        self.buffer.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeProcess:
    """Stand-in for ``asyncio.subprocess.Process`` with a controllable
    termination model so we can exercise both happy and force-kill paths."""

    next_pid = 32768

    def __init__(self, *, hang_on_terminate: bool = False) -> None:
        self.pid = _FakeProcess.next_pid
        _FakeProcess.next_pid += 1
        self.returncode: Optional[int] = None
        self.stdout = _FakeStdoutReader()
        self.stdin = _FakeStdinWriter()
        self.terminate_called = False
        self.kill_called = False
        self._hang_on_terminate = hang_on_terminate
        self._exit_event = asyncio.Event()

    def terminate(self) -> None:
        self.terminate_called = True
        if not self._hang_on_terminate:
            self.returncode = -15
            self._exit_event.set()

    def kill(self) -> None:
        self.kill_called = True
        self.returncode = -9
        self._exit_event.set()

    async def wait(self) -> int:
        await self._exit_event.wait()
        assert self.returncode is not None
        return self.returncode


class _FakeClientSession:
    """ClientSession stand-in. Ignores the bridged streams and returns a
    canned tool listing; tests can flip ``stall_initialize`` to drive the
    init-timeout path."""

    instances: List["_FakeClientSession"] = []
    stall_initialize: bool = False

    def __init__(self, read_stream: Any, write_stream: Any) -> None:
        self.read_stream = read_stream
        self.write_stream = write_stream
        self.initialize_called = False
        self.list_tools_called = False
        self.aexit_called = False
        self.tools: List[_FakeTool] = [
            _FakeTool(
                name="list_functions",
                description="Enumerate Ghidra functions",
                inputSchema={
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                },
            ),
            _FakeTool(
                name="decompile",
                description="Decompile a function",
                inputSchema={
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                    "required": ["address"],
                },
            ),
        ]
        _FakeClientSession.instances.append(self)

    async def __aenter__(self) -> "_FakeClientSession":
        return self

    async def __aexit__(self, *args: Any) -> None:
        self.aexit_called = True

    async def initialize(self) -> None:
        self.initialize_called = True
        if _FakeClientSession.stall_initialize:
            # Sleep longer than the manager's 10s init timeout would allow
            # in production. The test patches _INIT_TIMEOUT_SECONDS down to
            # exercise the timeout path quickly.
            await asyncio.sleep(60)

    async def list_tools(self) -> _FakeListing:
        self.list_tools_called = True
        return _FakeListing(tools=list(self.tools))


@pytest.fixture()
def mcp_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _FakeClientSession.instances.clear()
    _FakeClientSession.stall_initialize = False

    last_process: list[_FakeProcess] = []

    async def _fake_create(*args: Any, **kwargs: Any) -> _FakeProcess:
        proc = _FakeProcess()
        last_process.append(proc)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create)
    monkeypatch.setattr(mcp_runtime, "ClientSession", _FakeClientSession)
    yield


@pytest.fixture()
def manager(tmp_path: Path) -> Iterator[MCPClientManager]:
    config_path = tmp_path / "wintermute" / "mcp_servers.json"
    mgr = MCPClientManager(config_path=config_path)
    try:
        yield mgr
    finally:
        mgr.shutdown()


def _wait_running(mgr: MCPClientManager, name: str, timeout: float = 5.0) -> bool:
    """Poll until ``name`` shows up in running_servers (background start
    finishes) or ``timeout`` elapses. Tests should never sleep blindly."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if name in mgr.running_servers:
            return True
        time.sleep(0.02)
    return False


def _wait_absent(mgr: MCPClientManager, name: str, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if name not in mgr.running_servers:
            return True
        time.sleep(0.02)
    return False


# ---------------------------------------------------------------------------
# Rule 1: register is sync, never touches the loop
# ---------------------------------------------------------------------------


def test_register_does_not_touch_event_loop(
    tmp_path: Path,
) -> None:
    mgr = MCPClientManager(config_path=tmp_path / "mcp.json")
    try:
        # Before register: no loop, no thread.
        assert mgr.loop is None
        assert mgr._thread is None

        mgr.register_server("ghidra", "python", ["g.py"])

        # After register: still no loop spun up.
        assert mgr.loop is None
        assert mgr._thread is None
        assert mgr.config_path.is_file()
    finally:
        mgr.shutdown()


def test_register_persists_to_disk(manager: MCPClientManager) -> None:
    manager.register_server(
        name="ghidra",
        command="python",
        args=["ghidra_mcp.py"],
        env={"GHIDRA_HOME": "/opt/ghidra"},
    )
    saved = json.loads(manager.config_path.read_text())
    assert saved == [
        {
            "name": "ghidra",
            "command": "python",
            "args": ["ghidra_mcp.py"],
            "env": {"GHIDRA_HOME": "/opt/ghidra"},
        }
    ]


def test_register_overwrites_existing(manager: MCPClientManager) -> None:
    manager.register_server("ghidra", "python", ["v1.py"])
    manager.register_server("ghidra", "python", ["v2.py"])
    listed = manager.list_registered()
    assert len(listed) == 1
    assert listed[0].args == ["v2.py"]


def test_delete_removes_entry(manager: MCPClientManager) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    assert manager.delete_server("ghidra") is True
    assert manager.list_registered() == []
    assert manager.delete_server("ghidra") is False


def test_load_config_from_existing_file(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            [
                {
                    "name": "binja",
                    "command": "binja-mcp",
                    "args": ["--debug"],
                    "env": {},
                }
            ]
        )
    )
    mgr = MCPClientManager(config_path=config)
    try:
        listed = mgr.list_registered()
        assert len(listed) == 1
        assert listed[0].name == "binja"
    finally:
        mgr.shutdown()


def test_malformed_config_is_ignored(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text("{not json")
    mgr = MCPClientManager(config_path=config)
    try:
        assert mgr.list_registered() == []
    finally:
        mgr.shutdown()


# ---------------------------------------------------------------------------
# Rule 2: start_server returns immediately, async path runs in background
# ---------------------------------------------------------------------------


def test_start_server_returns_immediately(
    manager: MCPClientManager, mcp_env: None
) -> None:
    manager.register_server("ghidra", "python", ["g.py"])

    started_at = time.monotonic()
    message = manager.start_server("ghidra")
    elapsed = time.monotonic() - started_at

    assert isinstance(message, str)
    assert "Starting" in message
    # The UI thread must not be held by the handshake.
    assert elapsed < 0.5

    # The background task DOES finish; we just don't block on it.
    assert _wait_running(manager, "ghidra")


def test_start_server_eventually_lists_tools(
    manager: MCPClientManager, mcp_env: None
) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    state = manager.running_servers["ghidra"]
    assert state["process"] is not None
    assert state["process"].pid > 0
    assert len(state["tools"]) == 2

    fake_session = _FakeClientSession.instances[-1]
    assert fake_session.initialize_called is True
    assert fake_session.list_tools_called is True


def test_start_server_unregistered_returns_message(
    manager: MCPClientManager,
) -> None:
    msg = manager.start_server("nope")
    assert "not registered" in msg
    assert manager.loop is None  # No loop spun up for an invalid name.


def test_start_server_idempotent_when_running(
    manager: MCPClientManager, mcp_env: None
) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    msg = manager.start_server("ghidra")
    assert "already running" in msg


def test_start_server_handles_init_timeout(
    manager: MCPClientManager,
    monkeypatch: pytest.MonkeyPatch,
    mcp_env: None,
) -> None:
    """When session.initialize() hangs past _INIT_TIMEOUT_SECONDS, the manager
    must abort cleanly AND force-kill the subprocess."""
    monkeypatch.setattr(mcp_runtime, "_INIT_TIMEOUT_SECONDS", 0.3)
    _FakeClientSession.stall_initialize = True

    manager.register_server("flaky", "python", ["flaky.py"])
    manager.start_server("flaky")

    # Wait until the async start path has progressed far enough to have
    # constructed a ClientSession (otherwise we race past the test).
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and not _FakeClientSession.instances:
        time.sleep(0.02)
    assert _FakeClientSession.instances, "async start never reached ClientSession"
    fake_session = _FakeClientSession.instances[-1]

    # The init must time out → entry never lands in running_servers.
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if fake_session.aexit_called:
            break
        time.sleep(0.02)
    assert fake_session.aexit_called is True
    assert "flaky" not in manager.running_servers


def test_start_server_handles_spawn_failure(
    manager: MCPClientManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError("command not on PATH")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _boom)

    manager.register_server("missing", "nonexistent-binary", [])
    msg = manager.start_server("missing")
    assert "Starting" in msg

    # Wait for background task to settle; running_servers must remain empty.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if "missing" in manager.running_servers:  # pragma: no cover
            pytest.fail(
                "start should not have populated running_servers on spawn failure"
            )
        time.sleep(0.05)
    assert manager.get_status() == []


# ---------------------------------------------------------------------------
# Rule 3 & 4: stop_server force-kills the captured process
# ---------------------------------------------------------------------------


def test_stop_server_calls_terminate(manager: MCPClientManager, mcp_env: None) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    process = manager.running_servers["ghidra"]["process"]
    msg = manager.stop_server("ghidra")

    assert "Stopped" in msg
    assert "ghidra" not in manager.running_servers
    assert process.terminate_called is True
    # Graceful terminate succeeded -> kill() was NOT needed.
    assert process.kill_called is False


def test_stop_server_force_kills_when_terminate_hangs(
    manager: MCPClientManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the subprocess ignores SIGTERM, kill() must follow within 1s."""
    _FakeClientSession.instances.clear()
    _FakeClientSession.stall_initialize = False

    last_process: list[_FakeProcess] = []

    async def _fake_create(*args: Any, **kwargs: Any) -> _FakeProcess:
        proc = _FakeProcess(hang_on_terminate=True)
        last_process.append(proc)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create)
    monkeypatch.setattr(mcp_runtime, "ClientSession", _FakeClientSession)

    manager.register_server("zombie", "python", ["z.py"])
    manager.start_server("zombie")
    assert _wait_running(manager, "zombie")

    process = manager.running_servers["zombie"]["process"]
    msg = manager.stop_server("zombie")

    assert "Stopped" in msg
    assert "zombie" not in manager.running_servers
    assert process.terminate_called is True
    # SIGTERM was ignored, manager fell through to SIGKILL.
    assert process.kill_called is True
    assert process.returncode == -9


def test_stop_server_when_not_running(manager: MCPClientManager) -> None:
    msg = manager.stop_server("nope")
    assert "not running" in msg


def test_stop_server_is_bounded(manager: MCPClientManager, mcp_env: None) -> None:
    """stop_server must return within its own timeout, not block forever."""
    manager.register_server("ghidra", "python", ["g.py"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    started_at = time.monotonic()
    manager.stop_server("ghidra", timeout=2.0)
    elapsed = time.monotonic() - started_at
    # Even with a 2s ceiling, the fake process exits instantly.
    assert elapsed < 1.0


def test_delete_running_server_stops_first(
    manager: MCPClientManager, mcp_env: None
) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    process = manager.running_servers["ghidra"]["process"]
    assert manager.delete_server("ghidra") is True
    assert manager.list_registered() == []
    assert "ghidra" not in manager.running_servers
    assert process.terminate_called is True


# ---------------------------------------------------------------------------
# Status & external tool surface
# ---------------------------------------------------------------------------


def test_get_status_includes_pid(manager: MCPClientManager, mcp_env: None) -> None:
    manager.register_server("ghidra", "python", ["g.py", "--rpc"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    [entry] = manager.get_status()
    assert entry["name"] == "ghidra"
    assert entry["command"] == "python"
    assert entry["args"] == ["g.py", "--rpc"]
    assert entry["tools"] == 2
    assert isinstance(entry["pid"], int)
    assert entry["pid"] > 0


def test_get_all_external_tools_translates_to_toolspec(
    manager: MCPClientManager, mcp_env: None
) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    manager.start_server("ghidra")
    assert _wait_running(manager, "ghidra")

    specs = manager.get_all_external_tools()
    assert all(isinstance(s, ToolSpec) for s in specs)
    names = {s.name for s in specs}
    assert names == {"ghidra__list_functions", "ghidra__decompile"}


def test_get_all_external_tools_namespaced_per_server(
    manager: MCPClientManager, mcp_env: None
) -> None:
    manager.register_server("ghidra", "python", ["g.py"])
    manager.register_server("binja", "binja-mcp", [])
    manager.start_server("ghidra")
    manager.start_server("binja")
    assert _wait_running(manager, "ghidra")
    assert _wait_running(manager, "binja")

    specs = manager.get_all_external_tools()
    names = {s.name for s in specs}
    # Same upstream tool name appears once per server, namespaced.
    assert sum(1 for n in names if n.endswith("__list_functions")) == 2


def test_get_all_external_tools_empty_without_running(
    manager: MCPClientManager,
) -> None:
    assert manager.get_all_external_tools() == []


# ---------------------------------------------------------------------------
# Rule 5: shutdown stops everything and tears down the loop
# ---------------------------------------------------------------------------


def test_shutdown_stops_running_servers_and_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeClientSession.instances.clear()
    _FakeClientSession.stall_initialize = False

    async def _fake_create(*args: Any, **kwargs: Any) -> _FakeProcess:
        return _FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create)
    monkeypatch.setattr(mcp_runtime, "ClientSession", _FakeClientSession)

    mgr = MCPClientManager(config_path=tmp_path / "mcp.json")
    mgr.register_server("ghidra", "python", ["g.py"])
    mgr.start_server("ghidra")
    assert _wait_running(mgr, "ghidra")

    process = mgr.running_servers["ghidra"]["process"]
    thread = mgr._thread
    assert thread is not None and thread.is_alive()

    mgr.shutdown()

    assert mgr.running_servers == {}
    assert mgr.loop is None
    assert mgr._thread is None
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert process.terminate_called is True


# ---------------------------------------------------------------------------
# Stdio plumbing helpers (direct unit tests for the JSON-RPC pumps)
# ---------------------------------------------------------------------------


class _ScriptedStdoutReader:
    """Reader that yields a fixed list of byte chunks then EOF."""

    def __init__(self, chunks: List[bytes]) -> None:
        self._chunks = deque(chunks)

    async def read(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.popleft()


class _CapturingStdinWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


@dataclass
class _ProcWithStreams:
    stdout: Any
    stdin: Any


def test_stdout_pump_decodes_jsonrpc_frames() -> None:
    """``_stdout_to_session_stream`` parses newline-delimited JSON-RPC into
    SessionMessage instances and forwards garbage as exceptions."""

    async def _drive() -> List[Any]:
        # One valid frame split across two reads, then a malformed line, then
        # another valid frame, then EOF.
        valid = (
            b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",'
            b'"capabilities":{},"serverInfo":{"name":"x","version":"1"}}}\n'
        )
        chunks = [valid[:20], valid[20:], b"GARBAGE-NOT-JSON\n", valid, b""]
        process = _ProcWithStreams(
            stdout=_ScriptedStdoutReader(chunks),
            stdin=_CapturingStdinWriter(),
        )
        sender, receiver = anyio.create_memory_object_stream[Any](max_buffer_size=8)
        pump = asyncio.create_task(
            mcp_runtime._stdout_to_session_stream(
                cast(asyncio.subprocess.Process, process), sender
            )
        )

        collected: List[Any] = []
        async with receiver:
            async for item in receiver:
                collected.append(item)
        await pump
        return collected

    items = asyncio.run(_drive())
    # Expect: SessionMessage, Exception (parse error), SessionMessage.
    from mcp.shared.message import SessionMessage

    types = [type(x).__name__ for x in items]
    assert types[0] == "SessionMessage"
    assert isinstance(items[1], Exception)
    assert isinstance(items[2], SessionMessage)


def test_stdin_pump_serializes_messages_to_stdout() -> None:
    """``_session_stream_to_stdin`` serialises SessionMessage objects as
    newline-delimited JSON and writes them to ``process.stdin``."""

    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage

    async def _drive() -> bytearray:
        sender, receiver = anyio.create_memory_object_stream[Any](max_buffer_size=4)
        writer = _CapturingStdinWriter()
        process = _ProcWithStreams(stdout=_ScriptedStdoutReader([]), stdin=writer)
        pump = asyncio.create_task(
            mcp_runtime._session_stream_to_stdin(
                cast(asyncio.subprocess.Process, process), receiver
            )
        )

        msg = JSONRPCMessage.model_validate(
            {"jsonrpc": "2.0", "id": 7, "method": "ping"}
        )
        await sender.send(SessionMessage(message=msg))
        await sender.aclose()
        await pump
        return writer.buffer

    buffer = asyncio.run(_drive())
    assert buffer.endswith(b"\n")
    decoded = json.loads(buffer.decode("utf-8").strip())
    assert decoded["method"] == "ping"
    assert decoded["id"] == 7
