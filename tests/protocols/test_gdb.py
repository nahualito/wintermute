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

import socket
import threading
from collections.abc import Generator
from typing import Callable, Dict, List, Union

import pytest

from wintermute.protocols.gdb import (
    ARCH_REGISTERS,
    GDBClient,
    GDBConfig,
    GDBError,
    _detect_arch,
    _parse_register_blob,
)

# ---------------------------------------------------------------------------
# Fake GDB server for testing
# ---------------------------------------------------------------------------


class FakeGDBServer:
    """Minimal threaded TCP server that speaks GDB RSP for testing."""

    def __init__(
        self,
        responses: Union[Dict[str, str], None] = None,
        handler: Union[Callable[[str], str], None] = None,
    ) -> None:
        self.responses: Dict[str, str] = responses or {}
        self.handler = handler
        self.history: List[str] = []
        self._server_sock: Union[socket.socket, None] = None
        self._thread: Union[threading.Thread, None] = None
        self.port: int = 0

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("127.0.0.1", 0))
        self.port = self._server_sock.getsockname()[1]
        self._server_sock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._server_sock is not None
        self._server_sock.settimeout(5.0)
        try:
            conn, _ = self._server_sock.accept()
        except (socket.timeout, OSError):
            return
        conn.settimeout(5.0)
        try:
            while True:
                data = self._read_packet(conn)
                if data is None:
                    break
                self.history.append(data)
                if self.handler is not None:
                    reply = self.handler(data)
                elif data in self.responses:
                    reply = self.responses[data]
                else:
                    reply = ""
                self._send_reply(conn, reply)
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()

    @staticmethod
    def _read_packet(conn: socket.socket) -> str | None:
        buf = bytearray()
        while True:
            try:
                chunk = conn.recv(4096)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf.extend(chunk)

            raw = buf.decode("utf-8", errors="replace")
            # Handle interrupt byte (0x03) for halt.
            if b"\x03" in buf:
                return "\x03"

            start = 0
            while start < len(raw) and raw[start] in ("+", "-"):
                start += 1
            dollar = raw.find("$", start)
            if dollar == -1:
                continue
            hash_pos = raw.find("#", dollar + 1)
            if hash_pos == -1 or hash_pos + 2 >= len(raw):
                continue
            return raw[dollar + 1 : hash_pos]

    @staticmethod
    def _send_reply(conn: socket.socket, data: str) -> None:
        checksum = sum(ord(c) for c in data) & 0xFF
        frame = f"+${data}#{checksum:02x}"
        conn.sendall(frame.encode("utf-8"))

    def stop(self) -> None:
        if self._server_sock:
            self._server_sock.close()
        if self._thread:
            self._thread.join(timeout=2)


@pytest.fixture()
def gdb_server() -> Generator[FakeGDBServer, None, None]:
    server = FakeGDBServer()
    yield server
    server.stop()


def _make_client(server: FakeGDBServer) -> GDBClient:
    config = GDBConfig(host="127.0.0.1", port=server.port, default_timeout=3)
    return GDBClient(config)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGDBConfig:
    def test_defaults(self) -> None:
        cfg = GDBConfig()
        assert cfg.host == "localhost"
        assert cfg.port == 3333
        assert cfg.execution_timeout == 30

    def test_custom_values(self) -> None:
        cfg = GDBConfig(host="10.0.0.1", port=1234, execution_timeout=60)
        assert cfg.host == "10.0.0.1"
        assert cfg.port == 1234
        assert cfg.execution_timeout == 60


class TestChecksum:
    def test_known_checksums(self) -> None:
        assert GDBClient._checksum("g") == "67"
        assert GDBClient._checksum("OK") == "9a"
        assert GDBClient._checksum("m8000000,10") == "52"

    def test_empty(self) -> None:
        assert GDBClient._checksum("") == "00"


class TestGDBConnection:
    def test_connect_and_disconnect(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"?": "S05"}
        gdb_server.start()
        client = _make_client(gdb_server)
        client.connect()
        assert client.connected
        client.close()
        assert not client.connected

    def test_context_manager(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"?": "S05"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.connected
        assert not client.connected

    def test_connection_refused(self) -> None:
        config = GDBConfig(host="127.0.0.1", port=1, default_timeout=1)
        client = GDBClient(config)
        with pytest.raises(ConnectionError):
            client.connect()


class TestGDBRegisters:
    def test_read_registers(self, gdb_server: FakeGDBServer) -> None:
        reg_blob = "deadbeef" * 33
        gdb_server.responses = {"g": reg_blob}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            result = client.read_registers()
            assert result["raw"] == reg_blob
            assert result["zero"] == "0xefbeadde"
            assert result["ra"] == "0xefbeadde"
            assert result["pc"] == "0xefbeadde"
            assert "sp" in result
        assert "g" in gdb_server.history

    def test_read_single_register(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"p0": "deadbeef"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            result = client.read_register(0)
            assert result == "deadbeef"

    def test_write_register(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"P0=cafebabe": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.write_register(0, "cafebabe")

    def test_read_register_error(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"p0": "E01"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            with pytest.raises(GDBError, match="E01"):
                client.read_register(0)


class TestGDBMemory:
    def test_read_memory(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"m8000000,10": "deadbeefcafebabe" * 2}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            data = client.read_memory(0x8000000, 16)
            assert isinstance(data, bytes)
            assert len(data) == 16
        assert "m8000000,10" in gdb_server.history

    def test_write_memory(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"M8000000,4:deadbeef": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.write_memory(0x8000000, bytes.fromhex("deadbeef"))

    def test_write_memory_error(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"M8000000,4:deadbeef": "E03"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            with pytest.raises(GDBError, match="E03"):
                client.write_memory(0x8000000, bytes.fromhex("deadbeef"))


class TestGDBExecution:
    def test_single_step(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"s": "S05"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            reply = client.single_step()
            assert reply == "S05"

    def test_halt_interrupt(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"\x03": "T05"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            reply = client.halt()
            assert reply == "T05"

    def test_continue_returns_stop_reply(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"c": "S05"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            reply = client.continue_execution()
            assert reply == "S05"

    def test_get_stop_reason(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"?": "S00"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            reply = client.get_stop_reason()
            assert reply == "S00"


class TestGDBBreakpoints:
    def test_set_breakpoint(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"Z0,8000000,4": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.set_breakpoint(0x8000000)
        assert "Z0,8000000,4" in gdb_server.history

    def test_remove_breakpoint(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"z0,8000000,4": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.remove_breakpoint(0x8000000)

    def test_set_breakpoint_thumb(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"Z0,8000000,2": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.set_breakpoint(0x8000000, kind=2)

    def test_set_breakpoint_error(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"Z0,8000000,4": "E01"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            with pytest.raises(GDBError):
                client.set_breakpoint(0x8000000)


class TestGDBWatchpoints:
    def test_set_write_watchpoint(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"Z2,20000000,4": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.set_watchpoint(0x20000000, 4, "write")
        assert "Z2,20000000,4" in gdb_server.history

    def test_set_read_watchpoint(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"Z3,20000000,4": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.set_watchpoint(0x20000000, 4, "read")

    def test_set_access_watchpoint(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"Z4,20000000,4": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.set_watchpoint(0x20000000, 4, "access")

    def test_remove_watchpoint(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.responses = {"z2,20000000,4": "OK"}
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            assert client.remove_watchpoint(0x20000000, 4, "write")

    def test_invalid_watchpoint_type(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            with pytest.raises(ValueError, match="Unknown watchpoint type"):
                client.set_watchpoint(0x20000000, 4, "invalid")

    def test_invalid_remove_watchpoint_type(self, gdb_server: FakeGDBServer) -> None:
        gdb_server.start()
        client = _make_client(gdb_server)
        with client:
            with pytest.raises(ValueError, match="Unknown watchpoint type"):
                client.remove_watchpoint(0x20000000, 4, "bad")


# ---------------------------------------------------------------------------
# Register parsing and architecture detection
# ---------------------------------------------------------------------------


class TestRegisterParsing:
    def test_rv32_parse(self) -> None:
        blob = "01000000" * 33
        regs = _parse_register_blob(blob, ARCH_REGISTERS["rv32"][0], 4)
        assert regs["zero"] == "0x00000001"
        assert regs["pc"] == "0x00000001"
        assert regs["raw"] == blob

    def test_arm32_parse(self) -> None:
        blob = "efbeadde" * 17
        names, width = ARCH_REGISTERS["arm32"]
        regs = _parse_register_blob(blob, names, width)
        assert regs["r0"] == "0xdeadbeef"
        assert regs["cpsr"] == "0xdeadbeef"
        assert "pc" in regs

    def test_aarch64_parse(self) -> None:
        blob = "efbeaddeefbeadde" * 34
        names, width = ARCH_REGISTERS["aarch64"]
        regs = _parse_register_blob(blob, names, width)
        assert regs["x0"] == "0xdeadbeefdeadbeef"
        assert regs["pc"] in regs.values()

    def test_detect_rv32(self) -> None:
        names, width = _detect_arch(33 * 8)
        assert width == 4
        assert "ra" in names

    def test_detect_arm32(self) -> None:
        names, width = _detect_arch(17 * 8)
        assert width == 4
        assert "cpsr" in names

    def test_detect_aarch64(self) -> None:
        names, width = _detect_arch(34 * 16)
        assert width == 8
        assert "x0" in names

    def test_detect_unknown_falls_back_to_rv32(self) -> None:
        names, width = _detect_arch(7)
        assert width == 4
        assert names[0] == "zero"

    def test_explicit_arch_config(self, gdb_server: FakeGDBServer) -> None:
        blob = "efbeadde" * 17
        gdb_server.responses = {"g": blob}
        gdb_server.start()
        config = GDBConfig(
            host="127.0.0.1",
            port=gdb_server.port,
            arch="arm32",
        )
        client = GDBClient(config)
        with client:
            regs = client.read_registers()
            assert "r0" in regs
            assert "cpsr" in regs
            assert regs["r0"] == "0xdeadbeef"
