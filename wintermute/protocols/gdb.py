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


class GDBConfig(BaseModel):
    """Connection settings for a GDB Remote Serial Protocol server."""

    host: str = "localhost"
    port: int = Field(default=3333, ge=1, le=65535)
    encoding: str = "utf-8"
    default_timeout: int = Field(default=10, ge=1)
    execution_timeout: int = Field(default=30, ge=1)


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

    def read_registers(self) -> dict[str, str]:
        """Read all general-purpose registers.

        Returns a dictionary mapping ``"raw"`` to the full hex-encoded
        register file blob returned by the GDB ``g`` packet.
        """
        response = self._command("g")
        self._check_error(response)
        return {"raw": response}

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
