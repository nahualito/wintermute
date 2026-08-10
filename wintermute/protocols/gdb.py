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

import logging
import re
import socket
import time
from typing import Union

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

_STOP_REPLY = re.compile(r"^[STW]")

_RV32_REGS: list[str] = [
    "zero",
    "ra",
    "sp",
    "gp",
    "tp",
    "t0",
    "t1",
    "t2",
    "s0",
    "s1",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "s9",
    "s10",
    "s11",
    "t3",
    "t4",
    "t5",
    "t6",
    "pc",
]

_RV64_REGS: list[str] = list(_RV32_REGS)

_ARM32_REGS: list[str] = [
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "sp",
    "lr",
    "pc",
    "cpsr",
]

_AARCH64_REGS: list[str] = [
    *[f"x{i}" for i in range(31)],
    "sp",
    "pc",
    "cpsr",
]

ARCH_REGISTERS: dict[str, tuple[list[str], int]] = {
    "rv32": (_RV32_REGS, 4),
    "rv64": (_RV64_REGS, 8),
    "arm32": (_ARM32_REGS, 4),
    "aarch64": (_AARCH64_REGS, 8),
}


def _detect_arch(blob_len: int) -> tuple[list[str], int]:
    """Guess architecture from the ``g`` packet blob length."""
    hex_chars = blob_len
    candidates: dict[str, tuple[list[str], int]] = {
        name: (names, width)
        for name, (names, width) in ARCH_REGISTERS.items()
        if len(names) * width * 2 <= hex_chars
    }
    if not candidates:
        return (_RV32_REGS, 4)
    exact = [
        (names, width)
        for names, width in candidates.values()
        if len(names) * width * 2 == hex_chars
    ]
    if len(exact) == 1:
        return exact[0]
    return (_RV32_REGS, 4)


def _parse_register_blob(
    blob: str,
    names: list[str],
    reg_bytes: int = 4,
) -> dict[str, str]:
    """Parse a GDB ``g`` packet blob into named registers.

    Each register is ``reg_bytes`` bytes encoded as little-endian hex in
    the blob.  Returns a dict mapping register names to ``0x``-prefixed
    big-endian hex strings.  Any trailing data beyond the named
    registers is included under the ``"raw"`` key.
    """
    chars_per_reg = reg_bytes * 2
    regs: dict[str, str] = {}
    for i, name in enumerate(names):
        start = i * chars_per_reg
        end = start + chars_per_reg
        if end > len(blob):
            break
        le_hex = blob[start:end]
        value = int.from_bytes(bytes.fromhex(le_hex), "little")
        regs[name] = f"0x{value:0{chars_per_reg}x}"
    regs["raw"] = blob
    return regs


class GDBConfig(BaseModel):
    """Connection settings for a GDB Remote Serial Protocol server."""

    host: str = "localhost"
    port: int = Field(default=3333, ge=1, le=65535)
    encoding: str = "utf-8"
    default_timeout: int = Field(default=10, ge=1)
    execution_timeout: int = Field(default=30, ge=1)
    arch: str = Field(default="auto")
    register_names: list[str] = Field(default_factory=list)


class GDBError(RuntimeError):
    """Raised when the GDB server returns an error response."""


class GDBClient:
    """GDB Remote Serial Protocol client over TCP.

    Implements the subset of the GDB RSP needed for Renode debugging:
    register read/write, memory read/write, execution control, and
    breakpoint/watchpoint management.  The transport is lazy: the socket
    is opened on the first call to any operation that requires it.
    """

    def __init__(self, config: Union[GDBConfig, None] = None) -> None:
        self.config: GDBConfig = config or GDBConfig()
        self._sock: Union[socket.socket, None] = None

    # -- connection lifecycle -------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> None:
        if self._sock is not None:
            return
        try:
            sock = socket.create_connection(
                (self.config.host, self.config.port),
                timeout=self.config.default_timeout,
            )
        except OSError as exc:
            raise ConnectionError(
                f"Unable to reach GDB server at "
                f"{self.config.host}:{self.config.port}: {exc}"
            ) from exc
        self._sock = sock
        # Some GDB stubs send a greeting stop reply on connect; drain it.
        try:
            self._sock.settimeout(0.5)
            self._sock.recv(4096)
        except (socket.timeout, OSError):
            pass
        finally:
            self._sock.settimeout(self.config.default_timeout)

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                log.debug("Ignored error while closing GDB socket", exc_info=True)

    def __enter__(self) -> GDBClient:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- low-level protocol ---------------------------------------------------

    @staticmethod
    def _checksum(data: str) -> str:
        return f"{sum(ord(c) for c in data) & 0xFF:02x}"

    def _send_packet(self, data: str) -> None:
        self.connect()
        assert self._sock is not None
        frame = f"${data}#{self._checksum(data)}"
        self._sock.sendall(frame.encode(self.config.encoding))

    def _recv_packet(self, timeout: int | None = None) -> str:
        assert self._sock is not None
        effective_timeout = (
            timeout if timeout is not None else self.config.default_timeout
        )
        self._sock.settimeout(effective_timeout)
        deadline = time.monotonic() + effective_timeout
        buf = bytearray()

        # Read until we get a complete $data#xx packet.
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for GDB response")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout as exc:
                raise TimeoutError(f"Timed out reading from GDB server: {exc}") from exc
            if not chunk:
                raise ConnectionError("GDB server closed the connection")
            buf.extend(chunk)

            raw = buf.decode(self.config.encoding, errors="replace")
            # Skip leading ACK characters.
            start = 0
            while start < len(raw) and raw[start] in ("+", "-"):
                start += 1
            dollar = raw.find("$", start)
            if dollar == -1:
                continue
            hash_pos = raw.find("#", dollar + 1)
            if hash_pos == -1 or hash_pos + 2 >= len(raw):
                continue
            data = raw[dollar + 1 : hash_pos]
            # Send ACK.
            try:
                self._sock.sendall(b"+")
            except OSError:
                pass
            return data

    def _command(self, data: str, timeout: int | None = None) -> str:
        self._send_packet(data)
        return self._recv_packet(timeout)

    @staticmethod
    def _check_error(response: str) -> None:
        if response.startswith("E") and len(response) == 3:
            raise GDBError(f"GDB error: {response}")

    # -- register operations --------------------------------------------------

    def _resolve_register_map(self, blob: str) -> tuple[list[str], int]:
        """Pick register names and width from config or auto-detection."""
        if self.config.register_names:
            arch = self.config.arch
            if arch in ARCH_REGISTERS:
                _, width = ARCH_REGISTERS[arch]
            else:
                width = 4
            return (self.config.register_names, width)
        if self.config.arch != "auto" and self.config.arch in ARCH_REGISTERS:
            return ARCH_REGISTERS[self.config.arch]
        return _detect_arch(len(blob))

    def read_registers(self) -> dict[str, str]:
        """Read all general-purpose registers.

        Returns a dictionary mapping each register ABI name (e.g.
        ``"ra"``, ``"sp"``, ``"pc"``) to its ``0x``-prefixed value.
        A ``"raw"`` key holds the original hex blob.  The register
        layout is determined by the ``arch`` config (``"rv32"``,
        ``"rv64"``, ``"arm32"``, ``"aarch64"``) or auto-detected from
        the blob size.
        """
        response = self._command("g")
        self._check_error(response)
        names, width = self._resolve_register_map(response)
        return _parse_register_blob(response, names, width)

    def read_register(self, reg_num: int) -> str:
        """Read a single register by its GDB register number.

        Returns the hex-encoded value.
        """
        response = self._command(f"p{reg_num:x}")
        self._check_error(response)
        return response

    def write_register(self, reg_num: int, hex_value: str) -> bool:
        """Write a value to a single register.

        Args:
            reg_num: GDB register number.
            hex_value: Value as a hex string (no ``0x`` prefix).
        """
        response = self._command(f"P{reg_num:x}={hex_value}")
        self._check_error(response)
        return response == "OK"

    # -- memory operations ----------------------------------------------------

    def read_memory(self, address: int, length: int) -> bytes:
        """Read ``length`` bytes starting at ``address``.

        Returns raw bytes decoded from the hex response.
        """
        response = self._command(f"m{address:x},{length:x}")
        self._check_error(response)
        return bytes.fromhex(response)

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write ``data`` to memory at ``address``."""
        hex_data = data.hex()
        response = self._command(f"M{address:x},{len(data):x}:{hex_data}")
        self._check_error(response)
        return response == "OK"

    # -- execution control ----------------------------------------------------

    def continue_execution(self) -> str:
        """Resume execution and block until a stop reply arrives.

        If no stop reply arrives within ``config.execution_timeout``
        seconds, an interrupt (``\\x03``) is sent to force a halt and the
        resulting stop reply is returned.
        """
        self._send_packet("c")
        try:
            return self._recv_packet(timeout=self.config.execution_timeout)
        except TimeoutError:
            return self.halt()

    def single_step(self) -> str:
        """Execute a single instruction and return the stop reply."""
        return self._command("s", timeout=self.config.execution_timeout)

    def halt(self) -> str:
        """Send an interrupt to halt the target.

        Returns the stop reply.
        """
        assert self._sock is not None
        self.connect()
        self._sock.sendall(b"\x03")
        return self._recv_packet(timeout=self.config.default_timeout)

    # -- breakpoints ----------------------------------------------------------

    def set_breakpoint(self, address: int, kind: int = 4) -> bool:
        """Insert a software breakpoint at ``address``.

        Args:
            address: Target address.
            kind: Breakpoint kind (instruction length in bytes). 4 for
                ARM, 2 for Thumb.
        """
        response = self._command(f"Z0,{address:x},{kind:x}")
        self._check_error(response)
        return response == "OK"

    def remove_breakpoint(self, address: int, kind: int = 4) -> bool:
        """Remove a software breakpoint at ``address``."""
        response = self._command(f"z0,{address:x},{kind:x}")
        self._check_error(response)
        return response == "OK"

    def set_watchpoint(self, address: int, length: int, wp_type: str = "write") -> bool:
        """Insert a hardware watchpoint.

        Args:
            address: Watch address.
            length: Number of bytes to watch.
            wp_type: ``"write"``, ``"read"``, or ``"access"``.
        """
        type_code = {"write": "2", "read": "3", "access": "4"}.get(wp_type)
        if type_code is None:
            raise ValueError(f"Unknown watchpoint type: {wp_type!r}")
        response = self._command(f"Z{type_code},{address:x},{length:x}")
        self._check_error(response)
        return response == "OK"

    def remove_watchpoint(
        self, address: int, length: int, wp_type: str = "write"
    ) -> bool:
        """Remove a hardware watchpoint."""
        type_code = {"write": "2", "read": "3", "access": "4"}.get(wp_type)
        if type_code is None:
            raise ValueError(f"Unknown watchpoint type: {wp_type!r}")
        response = self._command(f"z{type_code},{address:x},{length:x}")
        self._check_error(response)
        return response == "OK"

    # -- query ----------------------------------------------------------------

    def get_stop_reason(self) -> str:
        """Query the current halt reason (``?`` packet)."""
        return self._command("?")


__all__ = [
    "GDBClient",
    "GDBConfig",
    "GDBError",
]
