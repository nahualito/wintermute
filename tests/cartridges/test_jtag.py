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

import hashlib
import re
import shutil
import socket
import threading
from pathlib import Path
from typing import Callable, Dict, List, Union

import pytest

from wintermute.cartridges.jtag import (
    JTAGCartridge,
    OpenOCDConfig,
    OpenOCDError,
    OpenOCDTransport,
    _check_openocd_installed,
)
from wintermute.utils.blob_manager import (
    BLOB_TYPE,
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


class FakeTransport(OpenOCDTransport):
    """In-memory transport that returns canned responses keyed by command."""

    def __init__(
        self,
        responses: Union[Dict[str, str], None] = None,
        handler: Union[Callable[[str], str], None] = None,
    ) -> None:
        super().__init__(OpenOCDConfig(default_timeout=1))
        self.responses: Dict[str, str] = responses or {}
        self.handler = handler
        self.history: List[str] = []

    def execute_command(self, cmd: str, timeout: int = 5) -> str:
        self.history.append(cmd)
        if self.handler is not None:
            return self.handler(cmd)
        if cmd in self.responses:
            return self.responses[cmd]
        # Match by prefix so e.g. "mdw 0x08000000 1" finds "mdw" entry.
        for prefix, response in self.responses.items():
            if cmd.startswith(prefix):
                return response
        return ""


# ---------------------------------------------------------------------------
# Dependency checking
# ---------------------------------------------------------------------------


def test_check_openocd_installed_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/openocd")
    assert _check_openocd_installed() is True


def test_check_openocd_installed_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert _check_openocd_installed() is False


def test_cartridge_init_raises_without_openocd(
    monkeypatch: pytest.MonkeyPatch, workspace: WorkspaceManager
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="OpenOCD"):
        JTAGCartridge()


def test_cartridge_init_skips_check_when_transport_injected(
    monkeypatch: pytest.MonkeyPatch, workspace: WorkspaceManager
) -> None:
    # Even with openocd missing, an injected transport is honored — useful
    # for unit testing and remote/proxy setups.
    monkeypatch.setattr(shutil, "which", lambda _: None)
    jtag = JTAGCartridge(transport=FakeTransport())
    assert jtag.transport is not None


# ---------------------------------------------------------------------------
# Transport (real loopback socket)
# ---------------------------------------------------------------------------


class _FakeOpenOCDServer:
    """Tiny TCP server that mimics OpenOCD's telnet protocol for tests."""

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
            conn.sendall(b"Open On-Chip Debugger\n> ")
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
    server = _FakeOpenOCDServer(scripted=["target halted due to debug-request\n> "])
    try:
        transport = OpenOCDTransport(
            OpenOCDConfig(host="127.0.0.1", port=server.port, default_timeout=2)
        )
        out = transport.execute_command("halt", timeout=2)
        transport.close()
    finally:
        server.close()
    assert out == "target halted due to debug-request"
    assert server.received == [b"halt"]


def test_transport_strips_command_echo() -> None:
    server = _FakeOpenOCDServer(scripted=["resume\nresumed\n> "])
    try:
        transport = OpenOCDTransport(
            OpenOCDConfig(host="127.0.0.1", port=server.port, default_timeout=2)
        )
        out = transport.execute_command("resume", timeout=2)
        transport.close()
    finally:
        server.close()
    assert out == "resumed"


def test_transport_connection_refused() -> None:
    # Bind a socket just to grab a free port, then close it so we know nothing
    # is listening there.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    free_port = sock.getsockname()[1]
    sock.close()
    transport = OpenOCDTransport(
        OpenOCDConfig(host="127.0.0.1", port=free_port, default_timeout=1)
    )
    with pytest.raises(ConnectionError):
        transport.execute_command("halt", timeout=1)


# ---------------------------------------------------------------------------
# JTAG cartridge methods
# ---------------------------------------------------------------------------


def test_halt_and_resume(workspace: WorkspaceManager) -> None:
    transport = FakeTransport(
        responses={
            "halt": "target halted due to debug-request, current mode: Thread",
            "resume": "",
        }
    )
    jtag = JTAGCartridge(transport=transport)

    assert jtag.halt_core() is True
    assert jtag.resume_core() is True
    assert transport.history == ["halt", "resume"]


def test_halt_raises_on_openocd_error(workspace: WorkspaceManager) -> None:
    transport = FakeTransport(responses={"halt": "Error: target not examined yet"})
    jtag = JTAGCartridge(transport=transport)
    with pytest.raises(OpenOCDError, match="halt"):
        jtag.halt_core()


def test_read_registers_parses_dump(workspace: WorkspaceManager) -> None:
    fake_reg_dump = (
        "===== arm v7m registers\n"
        "(0) r0 (/32): 0x00000000\n"
        "(1) r1 (/32): 0xDEADBEEF\n"
        "(2) r2 (/32): 0x12345678\n"
        "(15) pc (/32): 0x08000123\n"
        "(16) xPSR (/32): 0x01000000"
    )
    transport = FakeTransport(responses={"reg": fake_reg_dump})
    jtag = JTAGCartridge(transport=transport)
    regs = jtag.read_registers()
    assert regs == {
        "r0": "0x00000000",
        "r1": "0xDEADBEEF",
        "r2": "0x12345678",
        "pc": "0x08000123",
        "xPSR": "0x01000000",
    }


def test_read_memory_returns_cleaned_response(workspace: WorkspaceManager) -> None:
    transport = FakeTransport(
        responses={
            "mdw": "0x08000000: deadbeef cafebabe 12345678 90abcdef",
        }
    )
    jtag = JTAGCartridge(transport=transport)
    out = jtag.read_memory("0x08000000", word_count=4)
    assert out == "0x08000000: deadbeef cafebabe 12345678 90abcdef"
    assert transport.history == ["mdw 0x08000000 4"]


def test_read_memory_rejects_zero_word_count(workspace: WorkspaceManager) -> None:
    jtag = JTAGCartridge(transport=FakeTransport())
    with pytest.raises(ValueError):
        jtag.read_memory("0x08000000", word_count=0)


def test_write_memory_emits_mww(workspace: WorkspaceManager) -> None:
    transport = FakeTransport(responses={"mww": ""})
    jtag = JTAGCartridge(transport=transport)
    assert jtag.write_memory("0x20000000", "0xDEADBEEF") is True
    assert transport.history == ["mww 0x20000000 0xDEADBEEF"]


def test_write_memory_raises_on_error(workspace: WorkspaceManager) -> None:
    transport = FakeTransport(responses={"mww": "Error: failed to write memory"})
    jtag = JTAGCartridge(transport=transport)
    with pytest.raises(OpenOCDError):
        jtag.write_memory("0x20000000", "0xDEADBEEF")


# ---------------------------------------------------------------------------
# dump_firmware integration
# ---------------------------------------------------------------------------


def test_dump_firmware_registers_blob(workspace: WorkspaceManager) -> None:
    payload = b"\xaa\xbb\xcc\xdd" * 16  # 64 bytes
    expected_sha = hashlib.sha256(payload).hexdigest()

    def handler(cmd: str) -> str:
        match = re.match(
            r"^dump_image \{(?P<path>[^}]+)\} (?P<addr>\S+) (?P<size>\d+)$", cmd
        )
        assert match is not None, f"Unexpected command: {cmd!r}"
        target = Path(match.group("path"))
        size = int(match.group("size"))
        target.write_bytes(payload[:size])
        return f"dumped {size} bytes in 0.001s"

    transport = FakeTransport(handler=handler)
    jtag = JTAGCartridge(transport=transport, workspace=workspace)

    descriptor = jtag.dump_firmware("0x08000000", len(payload), filename="boot.bin")

    assert descriptor["type"] == BLOB_TYPE
    assert descriptor["size_bytes"] == len(payload)
    assert descriptor["sha256"] == expected_sha
    file_path = Path(str(descriptor["file_path"]))
    assert file_path.is_file()
    assert file_path.read_bytes() == payload
    assert file_path.suffix == ".bin"
    # Temp file should have been renamed away.
    leftover = list(workspace.root.glob(".pending-*"))
    assert leftover == []


def test_dump_firmware_cleans_up_on_openocd_error(workspace: WorkspaceManager) -> None:
    def handler(cmd: str) -> str:
        match = re.match(r"^dump_image \{(?P<path>[^}]+)\}", cmd)
        assert match is not None
        # Simulate OpenOCD writing a partial file then failing.
        Path(match.group("path")).write_bytes(b"\x00" * 8)
        return "Error: target not halted"

    jtag = JTAGCartridge(transport=FakeTransport(handler=handler), workspace=workspace)
    with pytest.raises(OpenOCDError):
        jtag.dump_firmware("0x08000000", 64)

    leftover = list(workspace.root.glob(".pending-*"))
    assert leftover == []


def test_dump_firmware_rejects_zero_size(workspace: WorkspaceManager) -> None:
    jtag = JTAGCartridge(transport=FakeTransport(), workspace=workspace)
    with pytest.raises(ValueError):
        jtag.dump_firmware("0x08000000", 0)


def test_dump_firmware_raises_when_file_missing(workspace: WorkspaceManager) -> None:
    # Handler claims success but never writes the file.
    transport = FakeTransport(handler=lambda _cmd: "")
    jtag = JTAGCartridge(transport=transport, workspace=workspace)
    with pytest.raises(RuntimeError, match="missing"):
        jtag.dump_firmware("0x08000000", 32)
