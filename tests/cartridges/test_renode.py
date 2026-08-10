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

import shutil
import socket
import threading
from pathlib import Path
from typing import Callable, Dict, List, Union

import pytest

from wintermute.cartridges.renode import (
    RenodeCartridge,
    RenodeError,
    RenodeMonitorConfig,
    RenodeMonitorTransport,
    _check_renode_installed,
)
from wintermute.protocols.gdb import GDBClient, GDBConfig
from wintermute.utils.blob_manager import (
    WorkspaceManager,
    set_default_workspace,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def workspace(tmp_path: Path) -> WorkspaceManager:
    manager = WorkspaceManager(root=tmp_path / "ws")
    set_default_workspace(manager)
    return manager


# ---------------------------------------------------------------------------
# Fake transports
# ---------------------------------------------------------------------------


class FakeMonitorTransport(RenodeMonitorTransport):
    """In-memory transport that returns canned responses keyed by command."""

    def __init__(
        self,
        responses: Union[Dict[str, str], None] = None,
        handler: Union[Callable[[str], str], None] = None,
    ) -> None:
        super().__init__(RenodeMonitorConfig(default_timeout=1))
        self.responses: Dict[str, str] = responses or {}
        self.handler = handler
        self.history: List[str] = []

    def execute_command(self, cmd: str, timeout: int = 10) -> str:
        self.history.append(cmd)
        if self.handler is not None:
            return self.handler(cmd)
        if cmd in self.responses:
            return self.responses[cmd]
        for prefix, response in self.responses.items():
            if cmd.startswith(prefix):
                return response
        return ""


class FakeGDBClient(GDBClient):
    """Fake GDB client that returns canned responses."""

    def __init__(
        self,
        responses: Union[Dict[str, object], None] = None,
    ) -> None:
        super().__init__(GDBConfig(default_timeout=1))
        self._responses: Dict[str, object] = responses or {}
        self.history: List[str] = []
        self._connected = True

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        self._connected = True

    def close(self) -> None:
        self._connected = False

    def read_registers(self) -> dict[str, str]:
        self.history.append("read_registers")
        result = self._responses.get(
            "read_registers", {"raw": "deadbeef" * 33, "zero": "0xefbeadde"}
        )
        assert isinstance(result, dict)
        return result

    def read_register(self, reg_num: int) -> str:
        self.history.append(f"read_register:{reg_num}")
        result = self._responses.get(f"read_register:{reg_num}", "deadbeef")
        assert isinstance(result, str)
        return result

    def write_register(self, reg_num: int, hex_value: str) -> bool:
        self.history.append(f"write_register:{reg_num}={hex_value}")
        return True

    def read_memory(self, address: int, length: int) -> bytes:
        self.history.append(f"read_memory:{address:x},{length}")
        result = self._responses.get(f"read_memory:{address:x},{length}")
        if isinstance(result, bytes):
            return result
        return b"\xde\xad\xbe\xef" * (length // 4 or 1)

    def write_memory(self, address: int, data: bytes) -> bool:
        self.history.append(f"write_memory:{address:x},{data.hex()}")
        return True

    def continue_execution(self) -> str:
        self.history.append("continue")
        result = self._responses.get("continue", "S05")
        assert isinstance(result, str)
        return result

    def single_step(self) -> str:
        self.history.append("step")
        result = self._responses.get("step", "S05")
        assert isinstance(result, str)
        return result

    def halt(self) -> str:
        self.history.append("halt")
        result = self._responses.get("halt", "T05")
        assert isinstance(result, str)
        return result

    def set_breakpoint(self, address: int, kind: int = 4) -> bool:
        self.history.append(f"set_breakpoint:{address:x}")
        return True

    def remove_breakpoint(self, address: int, kind: int = 4) -> bool:
        self.history.append(f"remove_breakpoint:{address:x}")
        return True

    def set_watchpoint(self, address: int, length: int, wp_type: str = "write") -> bool:
        self.history.append(f"set_watchpoint:{address:x},{length},{wp_type}")
        return True

    def remove_watchpoint(
        self, address: int, length: int, wp_type: str = "write"
    ) -> bool:
        self.history.append(f"remove_watchpoint:{address:x},{length},{wp_type}")
        return True


def _make_cartridge(
    responses: Union[Dict[str, str], None] = None,
    gdb_responses: Union[Dict[str, object], None] = None,
    workspace: Union[WorkspaceManager, None] = None,
    handler: Union[Callable[[str], str], None] = None,
    with_gdb: bool = True,
) -> tuple[RenodeCartridge, FakeMonitorTransport, FakeGDBClient | None]:
    monitor = FakeMonitorTransport(responses=responses, handler=handler)
    gdb: FakeGDBClient | None = None
    if with_gdb:
        gdb = FakeGDBClient(responses=gdb_responses)
    cart = RenodeCartridge(monitor=monitor, gdb=gdb, workspace=workspace)
    return cart, monitor, gdb


# ---------------------------------------------------------------------------
# Dependency checking
# ---------------------------------------------------------------------------


def test_check_renode_installed_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/renode")
    assert _check_renode_installed() is True


def test_check_renode_installed_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert _check_renode_installed() is False


def test_cartridge_init_raises_without_renode(
    monkeypatch: pytest.MonkeyPatch, workspace: WorkspaceManager
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="Renode"):
        RenodeCartridge()


def test_cartridge_init_skips_check_when_transport_injected(
    monkeypatch: pytest.MonkeyPatch, workspace: WorkspaceManager
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    cart = RenodeCartridge(monitor=FakeMonitorTransport())
    assert cart.monitor is not None


# ---------------------------------------------------------------------------
# Transport (real loopback socket)
# ---------------------------------------------------------------------------


class _FakeRenodeMonitorServer:
    """Tiny TCP server that mimics Renode's Monitor telnet protocol."""

    def __init__(self, scripted: List[str]) -> None:
        self.scripted = list(scripted)
        self.received: List[bytes] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            conn.sendall(b"Renode v1.15\n(monitor) ")
            buffer = b""
            while self.scripted:
                while b"\n" not in buffer:
                    chunk = conn.recv(1024)
                    if not chunk:
                        return
                    buffer += chunk
                line, _, buffer = buffer.partition(b"\n")
                self.received.append(line)
                response = self.scripted.pop(0)
                conn.sendall(response.encode("utf-8"))

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1)


def test_transport_executes_command_and_strips_prompt() -> None:
    server = _FakeRenodeMonitorServer(scripted=["Starting emulation...\n(monitor) "])
    try:
        transport = RenodeMonitorTransport(
            RenodeMonitorConfig(host="127.0.0.1", port=server.port, default_timeout=2)
        )
        out = transport.execute_command("start", timeout=2)
        transport.close()
    finally:
        server.close()
    assert out == "Starting emulation..."
    assert server.received == [b"start"]


def test_transport_strips_command_echo() -> None:
    server = _FakeRenodeMonitorServer(scripted=["pause\nPaused\n(monitor) "])
    try:
        transport = RenodeMonitorTransport(
            RenodeMonitorConfig(host="127.0.0.1", port=server.port, default_timeout=2)
        )
        out = transport.execute_command("pause", timeout=2)
        transport.close()
    finally:
        server.close()
    assert out == "Paused"


def test_transport_connection_refused() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    free_port = sock.getsockname()[1]
    sock.close()
    transport = RenodeMonitorTransport(
        RenodeMonitorConfig(host="127.0.0.1", port=free_port, default_timeout=1)
    )
    with pytest.raises(ConnectionError):
        transport.execute_command("start", timeout=1)


# ---------------------------------------------------------------------------
# Machine lifecycle
# ---------------------------------------------------------------------------


def test_load_platform_description(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(
        responses={"machine LoadPlatformDescription": ""}
    )
    assert cart.load_platform_description("/path/to/board.repl") is True
    assert monitor.history == ["machine LoadPlatformDescription @/path/to/board.repl"]


def test_load_platform_description_string(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(
        responses={"machine LoadPlatformDescriptionFromString": ""}
    )
    assert cart.load_platform_description_string("cpu: CPU.CortexM4") is True
    assert len(monitor.history) == 1
    assert "LoadPlatformDescriptionFromString" in monitor.history[0]


def test_load_script(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"include": ""})
    assert cart.load_script("/path/to/setup.resc") is True
    assert monitor.history == ["include @/path/to/setup.resc"]


def test_start_emulation(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"start": ""})
    assert cart.start_emulation() is True
    assert "start" in monitor.history


def test_pause_emulation(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"pause": ""})
    assert cart.pause_emulation() is True
    assert "pause" in monitor.history


def test_reset_emulation(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"machine Reset": ""})
    assert cart.reset_emulation() is True
    assert "machine Reset" in monitor.history


def test_execute_monitor_command_passthrough(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"peripherals": "uart0\nuart1\nspi0"})
    result = cart.execute_monitor_command("peripherals")
    assert result == "uart0\nuart1\nspi0"


def test_monitor_error_raises(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge(responses={"start": "Error: machine not created"})
    with pytest.raises(RenodeError, match="start"):
        cart.start_emulation()


# ---------------------------------------------------------------------------
# GDB server management
# ---------------------------------------------------------------------------


def test_start_gdb_server(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"machine StartGdbServer": ""})
    assert cart.start_gdb_server(port=3333) is True
    assert "machine StartGdbServer 3333" in monitor.history


def test_stop_gdb_server(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"machine StopGdbServer": ""})
    assert cart.stop_gdb_server() is True
    assert "machine StopGdbServer" in monitor.history


# ---------------------------------------------------------------------------
# GDB client operations
# ---------------------------------------------------------------------------


def test_gdb_connect_creates_client(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge(with_gdb=False)
    assert cart.gdb is None


def test_gdb_disconnect(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert gdb is not None
    assert gdb.connected
    cart.gdb_disconnect()
    assert not gdb.connected


def test_gdb_read_registers_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    result = cart.gdb_read_registers()
    assert "raw" in result
    assert gdb is not None
    assert "read_registers" in gdb.history


def test_gdb_read_register_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge(gdb_responses={"read_register:0": "cafebabe"})
    result = cart.gdb_read_register(0)
    assert result == "cafebabe"
    assert gdb is not None
    assert "read_register:0" in gdb.history


def test_gdb_write_register_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert cart.gdb_write_register(0, "deadbeef") is True
    assert gdb is not None
    assert "write_register:0=deadbeef" in gdb.history


def test_gdb_read_memory_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge(
        gdb_responses={"read_memory:8000000,16": b"\xaa" * 16}
    )
    result = cart.gdb_read_memory("0x08000000", 16)
    assert result == "aa" * 16
    assert gdb is not None
    assert "read_memory:8000000,16" in gdb.history


def test_gdb_write_memory_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert cart.gdb_write_memory("0x08000000", "deadbeef") is True
    assert gdb is not None
    assert "write_memory:8000000,deadbeef" in gdb.history


def test_gdb_set_breakpoint_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert cart.gdb_set_breakpoint("0x08000000") is True
    assert gdb is not None
    assert "set_breakpoint:8000000" in gdb.history


def test_gdb_remove_breakpoint_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert cart.gdb_remove_breakpoint("0x08000000") is True
    assert gdb is not None
    assert "remove_breakpoint:8000000" in gdb.history


def test_gdb_set_watchpoint_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert cart.gdb_set_watchpoint("0x20000000", 4, "write") is True
    assert gdb is not None
    assert "set_watchpoint:20000000,4,write" in gdb.history


def test_gdb_remove_watchpoint_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge()
    assert cart.gdb_remove_watchpoint("0x20000000", 4, "read") is True
    assert gdb is not None
    assert "remove_watchpoint:20000000,4,read" in gdb.history


def test_gdb_continue_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge(gdb_responses={"continue": "S05"})
    result = cart.gdb_continue()
    assert result == "S05"
    assert gdb is not None
    assert "continue" in gdb.history


def test_gdb_step_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge(gdb_responses={"step": "S05"})
    result = cart.gdb_step()
    assert result == "S05"
    assert gdb is not None
    assert "step" in gdb.history


def test_gdb_halt_delegates(workspace: WorkspaceManager) -> None:
    cart, _, gdb = _make_cartridge(gdb_responses={"halt": "T05"})
    result = cart.gdb_halt()
    assert result == "T05"
    assert gdb is not None
    assert "halt" in gdb.history


def test_gdb_requires_connection(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge(with_gdb=False)
    with pytest.raises(RuntimeError, match="not connected"):
        cart.gdb_read_registers()


# ---------------------------------------------------------------------------
# Sysbus memory operations
# ---------------------------------------------------------------------------


def test_sysbus_read_double_word(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(
        responses={"sysbus ReadDoubleWord": "0xDEADBEEF"}
    )
    result = cart.sysbus_read_double_word("0x08000000")
    assert result == "0xDEADBEEF"
    assert "sysbus ReadDoubleWord 0x08000000" in monitor.history


def test_sysbus_write_double_word(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus WriteDoubleWord": ""})
    assert cart.sysbus_write_double_word("0x08000000", "0xCAFEBABE") is True
    assert "sysbus WriteDoubleWord 0x08000000 0xCAFEBABE" in monitor.history


def test_sysbus_read_byte(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus ReadByte": "0xFF"})
    result = cart.sysbus_read_byte("0x08000000")
    assert result == "0xFF"


def test_sysbus_write_byte(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus WriteByte": ""})
    assert cart.sysbus_write_byte("0x08000000", "0x42") is True


def test_sysbus_read_word(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus ReadWord": "0xBEEF"})
    result = cart.sysbus_read_word("0x08000000")
    assert result == "0xBEEF"


def test_sysbus_write_word(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus WriteWord": ""})
    assert cart.sysbus_write_word("0x08000000", "0x1234") is True


def test_sysbus_error_raises(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge(
        responses={"sysbus ReadDoubleWord": "Error: invalid address"}
    )
    with pytest.raises(RenodeError, match="ReadDoubleWord"):
        cart.sysbus_read_double_word("0xFFFFFFFF")


# ---------------------------------------------------------------------------
# Fault injection
# ---------------------------------------------------------------------------


def test_inject_bit_flip(workspace: WorkspaceManager) -> None:
    call_count = 0

    def handler(cmd: str) -> str:
        nonlocal call_count
        call_count += 1
        if cmd.startswith("sysbus ReadDoubleWord"):
            return "0x00000001"
        return ""

    cart, monitor, _ = _make_cartridge(handler=handler)
    assert cart.inject_bit_flip("0x08000000", 0) is True
    assert any("ReadDoubleWord" in c for c in monitor.history)
    assert any("WriteDoubleWord" in c for c in monitor.history)
    write_cmd = [c for c in monitor.history if "WriteDoubleWord" in c][0]
    assert "0x00000000" in write_cmd


def test_inject_bit_flip_invalid_position(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge()
    with pytest.raises(ValueError, match="bit_position"):
        cart.inject_bit_flip("0x08000000", 32)


def test_inject_memory_corruption(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus WriteDoubleWord": ""})
    assert cart.inject_memory_corruption("0x08000000", "0xDEADBEEF") is True
    assert "sysbus WriteDoubleWord 0x08000000 0xDEADBEEF" in monitor.history


def test_set_peripheral_fault(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus.uart0 FaultInjection": ""})
    assert cart.set_peripheral_fault("uart0", "stuck_high") is True
    assert "sysbus.uart0 FaultInjection stuck_high" in monitor.history


# ---------------------------------------------------------------------------
# Firmware loading
# ---------------------------------------------------------------------------


def test_load_elf(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus LoadELF": ""})
    assert cart.load_elf("/path/to/firmware.elf") is True
    assert "sysbus LoadELF @/path/to/firmware.elf" in monitor.history


def test_load_binary(workspace: WorkspaceManager) -> None:
    cart, monitor, _ = _make_cartridge(responses={"sysbus LoadBinary": ""})
    assert cart.load_binary("/path/to/firmware.bin", "0x08000000") is True
    assert "sysbus LoadBinary @/path/to/firmware.bin 0x08000000" in monitor.history


def test_load_elf_error(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge(responses={"sysbus LoadELF": "Error: file not found"})
    with pytest.raises(RenodeError, match="LoadELF"):
        cart.load_elf("/nonexistent.elf")


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------


def test_dump_memory_region(workspace: WorkspaceManager) -> None:
    dump_data = b"\xde\xad\xbe\xef" * 64
    cart, _, _ = _make_cartridge(
        gdb_responses={f"read_memory:8000000,{len(dump_data)}": dump_data},
        workspace=workspace,
    )
    descriptor = cart.dump_memory_region("0x08000000", len(dump_data))
    assert "file_path" in descriptor
    assert descriptor["size_bytes"] == len(dump_data)
    assert "sha256" in descriptor


def test_dump_memory_region_rejects_zero(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge()
    with pytest.raises(ValueError, match="size_bytes"):
        cart.dump_memory_region("0x08000000", 0)


def test_dump_memory_region_requires_gdb(workspace: WorkspaceManager) -> None:
    cart, _, _ = _make_cartridge(with_gdb=False)
    with pytest.raises(RuntimeError, match="not connected"):
        cart.dump_memory_region("0x08000000", 256)


# ---------------------------------------------------------------------------
# CartridgeManager discovery
# ---------------------------------------------------------------------------


def test_cartridge_manager_discovers_renode() -> None:
    from wintermute.cartridges.manager import CartridgeManager

    manager = CartridgeManager()
    available = manager.list_available()
    assert "renode" in available
