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
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, Final, List, Union

from pydantic import BaseModel, Field

from wintermute.protocols.gdb import GDBClient, GDBConfig
from wintermute.utils.blob_manager import (
    WorkspaceManager,
    get_default_workspace,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------


def _check_renode_installed() -> bool:
    """Return ``True`` if the ``renode`` binary is available on ``PATH``."""
    return shutil.which("renode") is not None


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class RenodeMonitorConfig(BaseModel):
    """Connection settings for the Renode Monitor telnet console."""

    host: str = "localhost"
    port: int = Field(default=1234, ge=1, le=65535)
    prompt: str = "(monitor) "
    encoding: str = "utf-8"
    default_timeout: int = Field(default=10, ge=1)


_ERROR_LINE = re.compile(r"(?im)^\s*(?:Error|ERROR|Invalid)\b[: ]")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_TELNET_CMD = re.compile(rb"\xff[\xfb-\xfe].")
_RENODE_PROMPT = re.compile(r"\([A-Za-z0-9_.-]+\) $")


class RenodeError(RuntimeError):
    """Raised when the Renode Monitor reports an error."""


class RenodeMonitorTransport:
    """Manages a TCP socket connection to Renode's Monitor telnet console.

    The transport is lazy: the socket is opened on the first call to
    :meth:`execute_command`.  The banner and any pre-prompt chatter are
    drained automatically so callers only see the cleaned response body
    for the command they issued.
    """

    def __init__(self, config: Union[RenodeMonitorConfig, None] = None) -> None:
        self.config: RenodeMonitorConfig = config or RenodeMonitorConfig()
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
                f"Unable to reach Renode Monitor at "
                f"{self.config.host}:{self.config.port}: {exc}"
            ) from exc
        self._sock = sock
        try:
            self._read_until_prompt(self.config.default_timeout)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                log.debug(
                    "Ignored error while closing Renode Monitor socket",
                    exc_info=True,
                )

    def __enter__(self) -> RenodeMonitorTransport:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- IO -------------------------------------------------------------------

    def _negotiate_telnet(self, data: bytes) -> None:
        """Send proper telnet negotiation responses for IAC sequences."""
        if self._sock is None:
            return
        response = bytearray()
        i = 0
        while i < len(data) - 2:
            if data[i] == 0xFF and data[i + 1] in (0xFB, 0xFC, 0xFD, 0xFE):
                cmd = data[i + 1]
                opt = data[i + 2]
                if cmd == 0xFD:  # DO -> WILL
                    response.extend(bytes([0xFF, 0xFB, opt]))
                elif cmd == 0xFE:  # DONT -> WONT
                    response.extend(bytes([0xFF, 0xFC, opt]))
                elif cmd == 0xFB:  # WILL -> DO
                    response.extend(bytes([0xFF, 0xFD, opt]))
                elif cmd == 0xFC:  # WONT -> DONT
                    response.extend(bytes([0xFF, 0xFE, opt]))
                i += 3
            else:
                i += 1
        if response:
            try:
                self._sock.sendall(bytes(response))
            except OSError:
                log.debug("Failed to send telnet negotiation", exc_info=True)

    def drain_startup(
        self,
        timeout: int = 120,
        progress_cb: Union[Callable[[float, int], None], None] = None,
    ) -> str:
        """Drain remaining startup command output until the next prompt.

        After connecting, Renode may still be executing the ``-e``
        startup command (compiling C# peripherals, loading scripts).
        This method blocks until the next ``(monitor)`` prompt appears,
        discarding intermediate output.

        Args:
            timeout: Maximum seconds to wait for startup to finish.
            progress_cb: Called periodically with ``(elapsed_seconds,
                bytes_received)`` to report progress during long waits.

        Returns:
            The raw output from the startup command.
        """
        return self._read_until_prompt(timeout, progress_cb=progress_cb)

    @staticmethod
    def _strip_telnet(data: bytes) -> bytes:
        """Remove telnet negotiation sequences (IAC + cmd + option)."""
        return _TELNET_CMD.sub(b"", data)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Remove ANSI escape sequences from text."""
        return _ANSI_ESCAPE.sub("", text)

    def _read_until_prompt(
        self,
        timeout: int,
        progress_cb: Union[Callable[[float, int], None], None] = None,
    ) -> str:
        if self._sock is None:
            raise RuntimeError("RenodeMonitorTransport is not connected")
        start = time.monotonic()
        deadline = start + timeout
        buffer = bytearray()
        last_progress = start
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for Renode Monitor prompt after {timeout}s"
                )
            self._sock.settimeout(min(remaining, 5.0))
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                if progress_cb is not None:
                    elapsed = time.monotonic() - start
                    progress_cb(elapsed, len(buffer))
                    last_progress = time.monotonic()
                continue
            if not chunk:
                raise ConnectionError("Renode Monitor closed the connection")
            buffer.extend(chunk)
            self._negotiate_telnet(chunk)
            if progress_cb is not None:
                now = time.monotonic()
                if now - last_progress >= 5.0:
                    progress_cb(now - start, len(buffer))
                    last_progress = now
            cleaned = self._strip_telnet(buffer)
            text = cleaned.decode(self.config.encoding, errors="replace")
            stripped = self._strip_ansi(text)
            if _RENODE_PROMPT.search(stripped):
                break
        raw = self._strip_telnet(buffer)
        return raw.decode(self.config.encoding, errors="replace")

    def _clean_response(self, raw: str, cmd: str) -> str:
        text = self._strip_ansi(raw)
        match = _RENODE_PROMPT.search(text)
        if match:
            text = text[: match.start()]
        for echo in (cmd + "\r\n", cmd + "\n", cmd):
            if text.startswith(echo):
                text = text[len(echo) :]
                break
        return text.strip()

    def execute_command(self, cmd: str, timeout: int = 10) -> str:
        """Send ``cmd`` to the Renode Monitor and return the cleaned response.

        Args:
            cmd: The Monitor command to send (without a trailing newline).
            timeout: Maximum seconds to wait for the prompt.

        Returns:
            The response body stripped of the prompt and surrounding
            whitespace.
        """
        self.connect()
        if self._sock is None:
            raise RuntimeError("RenodeMonitorTransport is not connected")
        payload = (cmd + "\n").encode(self.config.encoding)
        self._sock.sendall(payload)
        raw = self._read_until_prompt(timeout)
        return self._clean_response(raw, cmd)


# ---------------------------------------------------------------------------
# Cartridge
# ---------------------------------------------------------------------------


_INSTALL_HINT: Final[str] = (
    "Renode binary not found on PATH. Install it from "
    "https://renode.io/ or build from source: "
    "https://github.com/renode/renode."
)


def _raise_if_error(response: str, command: str) -> None:
    if _ERROR_LINE.search(response):
        raise RenodeError(
            f"Renode reported an error for `{command}`: {response.strip()}"
        )


class RenodeCartridge:
    """Agentic Renode emulation operations.

    The cartridge composes a :class:`RenodeMonitorTransport` for machine
    management, a :class:`~wintermute.protocols.gdb.GDBClient` for
    debugging via GDB Remote Serial Protocol, and a
    :class:`~wintermute.utils.blob_manager.WorkspaceManager` for bulk
    artefacts.

    Each public method is strictly typed and carries a Google-style
    docstring so that
    :func:`wintermute.ai.utils.tool_factory.function_to_tool` can
    expose it to the AI as a JSON-schema tool.
    """

    def __init__(
        self,
        monitor: Union[RenodeMonitorTransport, None] = None,
        gdb: Union[GDBClient, None] = None,
        workspace: Union[WorkspaceManager, None] = None,
    ) -> None:
        if monitor is None:
            if not _check_renode_installed():
                raise RuntimeError(_INSTALL_HINT)
            monitor = RenodeMonitorTransport()
        self.monitor: RenodeMonitorTransport = monitor
        self.gdb: Union[GDBClient, None] = gdb
        self.workspace: WorkspaceManager = workspace or get_default_workspace()
        self._process: Union[subprocess.Popen[bytes], None] = None

    # -- process lifecycle ----------------------------------------------------

    def launch(
        self,
        startup_command: str = "",
        monitor_port: int = 1234,
        extra_args: Union[List[str], None] = None,
        startup_timeout: int = 300,
    ) -> bool:
        """Launch Renode as a subprocess and connect the Monitor transport.

        Starts ``renode --disable-xwt --port <monitor_port>`` with an
        optional ``-e`` startup command.  Waits for the Monitor telnet
        port to become available, then connects the transport.

        Args:
            startup_command: Renode commands to execute at startup
                (passed via ``-e``).  May include variable assignments,
                ``include`` directives, and macro calls separated by
                semicolons.
            monitor_port: TCP port for the Monitor telnet console.
            extra_args: Additional CLI arguments for the ``renode``
                binary.
            startup_timeout: Maximum seconds to wait for the startup
                command to finish.  C# peripheral compilation on a
                cold cache can take several minutes.  Defaults to 300.

        Returns:
            ``True`` if Renode started and the Monitor connected.
        """
        if self._process is not None and self._process.poll() is None:
            raise RuntimeError("Renode is already running")

        if not _check_renode_installed():
            raise RuntimeError(_INSTALL_HINT)

        cmd: List[str] = [
            "renode",
            "--disable-xwt",
            "--port",
            str(monitor_port),
        ]
        if startup_command:
            cmd.extend(["-e", startup_command])
        if extra_args:
            cmd.extend(extra_args)

        log.info("Launching Renode: %s", " ".join(cmd))
        print(
            "[*] Starting Renode... (first run may compile C# peripherals, "
            "this can take several minutes)"
        )
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        config = RenodeMonitorConfig(
            host="127.0.0.1", port=monitor_port, default_timeout=startup_timeout
        )
        deadline = time.monotonic() + startup_timeout
        connected = False
        poll_start = time.monotonic()
        last_msg = poll_start
        while time.monotonic() < deadline:
            try:
                sock = socket.create_connection((config.host, config.port), timeout=1)
                sock.close()
                connected = True
                break
            except OSError:
                if self._process.poll() is not None:
                    stderr_text = ""
                    if self._process.stderr is not None:
                        raw = self._process.stderr.read()
                        if isinstance(raw, bytes):
                            stderr_text = raw.decode(errors="replace")
                    raise RuntimeError(
                        f"Renode exited with code {self._process.returncode}: "
                        f"{stderr_text}"
                    )
                now = time.monotonic()
                if now - last_msg >= 10.0:
                    elapsed = int(now - poll_start)
                    print(
                        f"[*] Waiting for Renode Monitor port {monitor_port}... "
                        f"({elapsed}s elapsed)"
                    )
                    last_msg = now
                time.sleep(0.5)

        if not connected:
            self.shutdown()
            raise TimeoutError(
                f"Renode Monitor did not become available on port {monitor_port} "
                f"within {startup_timeout} seconds"
            )

        print("[+] Renode Monitor port is up, connecting...")
        self.monitor = RenodeMonitorTransport(config)
        self.monitor.connect()
        log.info("Connected to Renode Monitor on port %d", monitor_port)

        if startup_command:
            print("[*] Executing startup command (compiling peripherals)...")

            def _progress(elapsed: float, nbytes: int) -> None:
                print(
                    f"[*] Still loading... {elapsed:.0f}s elapsed, "
                    f"{nbytes} bytes received"
                )

            self.monitor.drain_startup(timeout=startup_timeout, progress_cb=_progress)
            print("[+] Startup command completed")

        return True

    def shutdown(self) -> bool:
        """Stop the Renode subprocess and disconnect transports.

        Sends ``quit`` to the Monitor if connected, then terminates the
        process.

        Returns:
            ``True`` if shutdown completed.
        """
        if self.gdb is not None and self.gdb.connected:
            try:
                self.gdb.close()
            except OSError:
                pass

        if self.monitor.connected:
            try:
                self.monitor.execute_command("quit")
            except (OSError, ConnectionError, TimeoutError):
                pass
            self.monitor.close()

        if self._process is not None:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=2)
            self._process = None

        return True

    @property
    def running(self) -> bool:
        """Whether the Renode subprocess is alive."""
        return self._process is not None and self._process.poll() is None

    # -- UART console ---------------------------------------------------------

    def read_uart_console(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        timeout: float = 2.0,
    ) -> str:
        """Read available data from a Renode socket terminal.

        Renode's ``emulation CreateServerSocketTerminal`` exposes UART
        output on a TCP port.  This method connects, reads whatever is
        buffered, and returns it as a string.

        Args:
            host: Socket terminal host.
            port: Socket terminal port (set in the ``.resc`` script).
            timeout: Seconds to wait for data.

        Returns:
            The decoded UART output, or an empty string if nothing was
            available.
        """
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise ConnectionError(
                f"Cannot reach UART socket terminal at {host}:{port}: {exc}"
            ) from exc
        try:
            sock.settimeout(timeout)
            chunks: List[bytes] = []
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except socket.timeout:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")
        finally:
            sock.close()

    # -- machine lifecycle (Monitor) ------------------------------------------

    def load_platform_description(self, repl_path: str) -> bool:
        """Load a Renode platform description (.repl) file.

        Sends ``machine LoadPlatformDescription @<path>`` to the Renode
        Monitor.

        Args:
            repl_path: Absolute or Renode-relative path to the ``.repl`` file.

        Returns:
            ``True`` if the command succeeded without error.
        """
        cmd = f"machine LoadPlatformDescription @{repl_path}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def load_platform_description_string(self, description: str) -> bool:
        """Load a platform description from an inline string.

        Sends ``machine LoadPlatformDescriptionFromString`` with the
        description text.

        Args:
            description: The platform description content.

        Returns:
            ``True`` if the command succeeded without error.
        """
        escaped = description.replace('"', '\\"')
        cmd = f'machine LoadPlatformDescriptionFromString "{escaped}"'
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def load_script(self, resc_path: str) -> bool:
        """Execute a Renode script (.resc) file.

        Sends ``include @<path>`` to the Monitor.

        Args:
            resc_path: Absolute or Renode-relative path to the ``.resc`` file.

        Returns:
            ``True`` if the script executed without error.
        """
        cmd = f"include @{resc_path}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def start_emulation(self) -> bool:
        """Start the emulated machine.

        Sends the ``start`` command to the Monitor.

        Returns:
            ``True`` if the command succeeded.
        """
        response = self.monitor.execute_command("start")
        _raise_if_error(response, "start")
        return True

    def pause_emulation(self) -> bool:
        """Pause the emulated machine.

        Sends the ``pause`` command to the Monitor.

        Returns:
            ``True`` if the command succeeded.
        """
        response = self.monitor.execute_command("pause")
        _raise_if_error(response, "pause")
        return True

    def reset_emulation(self) -> bool:
        """Reset the emulated machine to its initial state.

        Sends ``machine Reset`` to the Monitor.

        Returns:
            ``True`` if the command succeeded.
        """
        response = self.monitor.execute_command("machine Reset")
        _raise_if_error(response, "machine Reset")
        return True

    def execute_monitor_command(self, command: str, timeout: int = 30) -> str:
        """Send an arbitrary command to the Renode Monitor.

        This is the escape hatch for commands not covered by other
        methods.

        Args:
            command: The raw Monitor command to send.
            timeout: Maximum seconds to wait for the response.

        Returns:
            The cleaned response text.
        """
        return self.monitor.execute_command(command, timeout=timeout)

    # -- GDB server management (Monitor) --------------------------------------

    def start_gdb_server(self, port: int = 3333) -> bool:
        """Start the Renode built-in GDB server.

        Sends ``machine StartGdbServer <port>`` to the Monitor.

        Args:
            port: TCP port for the GDB server. Defaults to 3333.

        Returns:
            ``True`` if the command succeeded.
        """
        cmd = f"machine StartGdbServer {port}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def stop_gdb_server(self) -> bool:
        """Stop the Renode built-in GDB server.

        Returns:
            ``True`` if the command succeeded.
        """
        cmd = "machine StopGdbServer"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    # -- GDB client operations ------------------------------------------------

    def gdb_connect(self, host: str = "localhost", port: int = 3333) -> bool:
        """Connect the GDB client to a running GDB server.

        Creates a new :class:`~wintermute.protocols.gdb.GDBClient`
        instance and opens the connection.

        Args:
            host: GDB server hostname or IP.
            port: GDB server TCP port.

        Returns:
            ``True`` if the connection succeeded.
        """
        config = GDBConfig(host=host, port=port)
        self.gdb = GDBClient(config)
        self.gdb.connect()
        return True

    def gdb_disconnect(self) -> bool:
        """Disconnect the GDB client.

        Returns:
            ``True`` if the client was disconnected (or was already
            disconnected).
        """
        if self.gdb is not None:
            self.gdb.close()
        return True

    def _require_gdb(self) -> GDBClient:
        if self.gdb is None or not self.gdb.connected:
            raise RuntimeError("GDB client is not connected. Call gdb_connect() first.")
        return self.gdb

    def gdb_read_registers(self) -> Dict[str, str]:
        """Read all general-purpose registers via the GDB client.

        Returns:
            A dictionary mapping each register ABI name (e.g. ``"ra"``,
            ``"sp"``, ``"pc"``) to its ``0x``-prefixed value.  A
            ``"raw"`` key holds the original hex blob.
        """
        return self._require_gdb().read_registers()

    def gdb_read_register(self, register_number: int) -> str:
        """Read a single register by its GDB register number.

        Args:
            register_number: The GDB register index.

        Returns:
            The hex-encoded register value.
        """
        return self._require_gdb().read_register(register_number)

    def gdb_write_register(self, register_number: int, hex_value: str) -> bool:
        """Write a value to a single register.

        Args:
            register_number: The GDB register index.
            hex_value: Value as a hex string (no ``0x`` prefix).

        Returns:
            ``True`` if the write was acknowledged.
        """
        return self._require_gdb().write_register(register_number, hex_value)

    def gdb_read_memory(self, address: str, length: int) -> str:
        """Read memory via the GDB client.

        Args:
            address: Memory address as a hex string (e.g. ``"0x08000000"``).
            length: Number of bytes to read.

        Returns:
            Hex-encoded memory contents.
        """
        addr = int(address, 16) if address.startswith("0x") else int(address)
        data = self._require_gdb().read_memory(addr, length)
        return data.hex()

    def gdb_write_memory(self, address: str, hex_data: str) -> bool:
        """Write memory via the GDB client.

        Args:
            address: Memory address as a hex string (e.g. ``"0x08000000"``).
            hex_data: Data to write as a hex string (no ``0x`` prefix).

        Returns:
            ``True`` if the write was acknowledged.
        """
        addr = int(address, 16) if address.startswith("0x") else int(address)
        return self._require_gdb().write_memory(addr, bytes.fromhex(hex_data))

    def gdb_set_breakpoint(self, address: str) -> bool:
        """Set a software breakpoint at the given address.

        Args:
            address: Target address as a hex string (e.g. ``"0x08000000"``).

        Returns:
            ``True`` if the breakpoint was set.
        """
        addr = int(address, 16) if address.startswith("0x") else int(address)
        return self._require_gdb().set_breakpoint(addr)

    def gdb_remove_breakpoint(self, address: str) -> bool:
        """Remove a software breakpoint at the given address.

        Args:
            address: Target address as a hex string.

        Returns:
            ``True`` if the breakpoint was removed.
        """
        addr = int(address, 16) if address.startswith("0x") else int(address)
        return self._require_gdb().remove_breakpoint(addr)

    def gdb_set_watchpoint(
        self, address: str, length: int, watch_type: str = "write"
    ) -> bool:
        """Set a hardware watchpoint.

        Args:
            address: Watch address as a hex string.
            length: Number of bytes to watch.
            watch_type: ``"write"``, ``"read"``, or ``"access"``.

        Returns:
            ``True`` if the watchpoint was set.
        """
        addr = int(address, 16) if address.startswith("0x") else int(address)
        return self._require_gdb().set_watchpoint(addr, length, watch_type)

    def gdb_remove_watchpoint(
        self, address: str, length: int, watch_type: str = "write"
    ) -> bool:
        """Remove a hardware watchpoint.

        Args:
            address: Watch address as a hex string.
            length: Number of bytes to watch.
            watch_type: ``"write"``, ``"read"``, or ``"access"``.

        Returns:
            ``True`` if the watchpoint was removed.
        """
        addr = int(address, 16) if address.startswith("0x") else int(address)
        return self._require_gdb().remove_watchpoint(addr, length, watch_type)

    def gdb_continue(self) -> str:
        """Resume execution and wait for a stop event.

        Blocks until the emulated CPU hits a breakpoint, receives a
        signal, or the execution timeout expires (at which point the
        target is forcibly halted).

        Returns:
            The GDB stop reply string describing the halt reason.
        """
        return self._require_gdb().continue_execution()

    def gdb_step(self) -> str:
        """Execute a single instruction.

        Returns:
            The GDB stop reply string.
        """
        return self._require_gdb().single_step()

    def gdb_halt(self) -> str:
        """Halt the emulated CPU.

        Sends an interrupt to the GDB server to stop the target.

        Returns:
            The GDB stop reply string.
        """
        return self._require_gdb().halt()

    # -- memory via Monitor (sysbus) ------------------------------------------

    def sysbus_read_byte(self, address: str) -> str:
        """Read a single byte from the system bus.

        Args:
            address: Memory address as a hex string.

        Returns:
            The value as a string.
        """
        cmd = f"sysbus ReadByte {address}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return response

    def sysbus_read_word(self, address: str) -> str:
        """Read a 16-bit word from the system bus.

        Args:
            address: Memory address as a hex string.

        Returns:
            The value as a string.
        """
        cmd = f"sysbus ReadWord {address}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return response

    def sysbus_read_double_word(self, address: str) -> str:
        """Read a 32-bit double word from the system bus.

        Args:
            address: Memory address as a hex string.

        Returns:
            The value as a string.
        """
        cmd = f"sysbus ReadDoubleWord {address}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return response

    def sysbus_write_byte(self, address: str, value: str) -> bool:
        """Write a single byte to the system bus.

        Args:
            address: Memory address as a hex string.
            value: Value to write.

        Returns:
            ``True`` if the write succeeded.
        """
        cmd = f"sysbus WriteByte {address} {value}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def sysbus_write_word(self, address: str, value: str) -> bool:
        """Write a 16-bit word to the system bus.

        Args:
            address: Memory address as a hex string.
            value: Value to write.

        Returns:
            ``True`` if the write succeeded.
        """
        cmd = f"sysbus WriteWord {address} {value}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def sysbus_write_double_word(self, address: str, value: str) -> bool:
        """Write a 32-bit double word to the system bus.

        Args:
            address: Memory address as a hex string.
            value: Value to write.

        Returns:
            ``True`` if the write succeeded.
        """
        cmd = f"sysbus WriteDoubleWord {address} {value}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    # -- fault injection ------------------------------------------------------

    def inject_bit_flip(self, address: str, bit_position: int) -> bool:
        """Inject a single-bit flip at a memory address.

        Reads the current 32-bit value at ``address``, XORs it with
        ``1 << bit_position``, and writes it back.  Emulates a
        single-event upset (SEU).

        Args:
            address: Memory address as a hex string.
            bit_position: Bit index to flip (0-31).

        Returns:
            ``True`` if the injection succeeded.
        """
        if not 0 <= bit_position <= 31:
            raise ValueError("bit_position must be 0-31")
        current = self.sysbus_read_double_word(address)
        value = int(current.strip(), 0)
        flipped = value ^ (1 << bit_position)
        self.sysbus_write_double_word(address, f"0x{flipped:08X}")
        return True

    def inject_memory_corruption(self, address: str, hex_value: str) -> bool:
        """Write an arbitrary value to a memory address.

        Simulates a physical glitching attack or corrupted flash by
        writing ``hex_value`` directly to the system bus.

        Args:
            address: Memory address as a hex string.
            hex_value: Value to write (e.g. ``"0xDEADBEEF"``).

        Returns:
            ``True`` if the write succeeded.
        """
        self.sysbus_write_double_word(address, hex_value)
        return True

    def set_peripheral_fault(self, peripheral_name: str, fault_type: str) -> bool:
        """Configure a peripheral fault mode in the emulation.

        Sends a fault injection command to the named peripheral via the
        Monitor.

        Args:
            peripheral_name: Name of the Renode peripheral (e.g. ``"uart0"``).
            fault_type: Fault type string understood by the peripheral.

        Returns:
            ``True`` if the command succeeded.
        """
        cmd = f"sysbus.{peripheral_name} FaultInjection {fault_type}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    # -- firmware loading -----------------------------------------------------

    def load_elf(self, elf_path: str) -> bool:
        """Load an ELF binary into the emulated machine.

        Sends ``sysbus LoadELF @<path>`` to the Monitor.

        Args:
            elf_path: Path to the ELF file.

        Returns:
            ``True`` if the load succeeded.
        """
        cmd = f"sysbus LoadELF @{elf_path}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    def load_binary(self, bin_path: str, load_address: str) -> bool:
        """Load a raw binary into the emulated machine at a specific address.

        Sends ``sysbus LoadBinary @<path> <address>`` to the Monitor.

        Args:
            bin_path: Path to the binary file.
            load_address: Target address as a hex string.

        Returns:
            ``True`` if the load succeeded.
        """
        cmd = f"sysbus LoadBinary @{bin_path} {load_address}"
        response = self.monitor.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    # -- bulk operations ------------------------------------------------------

    def dump_memory_region(
        self,
        start_address: str,
        size_bytes: int,
        filename: str = "renode_dump.bin",
    ) -> Dict[str, Union[str, int]]:
        """Dump a memory region to disk.

        Reads ``size_bytes`` bytes starting at ``start_address`` via the
        GDB client and writes them to the workspace directory.  The file
        is adopted by the
        :class:`~wintermute.utils.blob_manager.WorkspaceManager` and a
        JSON descriptor is returned.

        Args:
            start_address: Memory address as a hex string.
            size_bytes: Number of bytes to dump. Must be positive.
            filename: Hint for the output filename.

        Returns:
            A descriptor dictionary with ``file_path``, ``size_bytes``,
            ``sha256``, and ``type`` keys.
        """
        if size_bytes < 1:
            raise ValueError("size_bytes must be >= 1")

        addr = (
            int(start_address, 16)
            if start_address.startswith("0x")
            else int(start_address)
        )

        gdb = self._require_gdb()
        data = gdb.read_memory(addr, size_bytes)

        workspace_root = self.workspace.root
        workspace_root.mkdir(parents=True, exist_ok=True)
        safe_basename = Path(filename).name or "renode_dump.bin"
        suffix = Path(safe_basename).suffix or ".bin"
        temp_path = workspace_root / f".pending-{os.getpid()}-{safe_basename}"

        try:
            temp_path.write_bytes(data)
            descriptor = self.workspace.register_file(temp_path, suffix=suffix)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

        log.info(
            "Dumped %d bytes from %s into %s",
            size_bytes,
            start_address,
            descriptor["file_path"],
        )
        return descriptor


__all__ = [
    "RenodeCartridge",
    "RenodeError",
    "RenodeMonitorConfig",
    "RenodeMonitorTransport",
    "_check_renode_installed",
]
