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
import time
from pathlib import Path
from typing import Dict, Final, Union

from pydantic import BaseModel, Field

from wintermute.utils.blob_manager import (
    WorkspaceManager,
    get_default_workspace,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------


def _check_openocd_installed() -> bool:
    """Return ``True`` if the ``openocd`` binary is available on ``PATH``.

    Returns:
        Whether ``shutil.which('openocd')`` resolves to a real executable.
    """
    return shutil.which("openocd") is not None


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class OpenOCDConfig(BaseModel):
    """Connection settings for the OpenOCD telnet/RPC console.

    OpenOCD's default telnet console listens on ``localhost:4444`` and
    terminates each response with a ``> `` prompt. The values here are the
    OpenOCD defaults; override them to point at a remote rig or a custom
    build that uses a different prompt.
    """

    host: str = "localhost"
    port: int = Field(default=4444, ge=1, le=65535)
    prompt: str = "> "
    encoding: str = "utf-8"
    default_timeout: int = Field(default=5, ge=1)


_REGISTER_LINE = re.compile(
    r"^\s*(?:\(\d+\)\s+)?(?P<name>[\w\.\-]+)\s*\(/\d+\):\s*(?P<value>0x[0-9a-fA-F]+)",
    re.MULTILINE,
)
_ERROR_LINE = re.compile(r"(?im)^\s*(?:Error|ERROR)\b[: ]")


class OpenOCDError(RuntimeError):
    """Raised when OpenOCD reports an error in a command response."""


class OpenOCDTransport:
    """Manages a TCP socket connection to OpenOCD's telnet console.

    The transport is lazy: the socket is opened on the first call to
    :meth:`execute_command`. The banner and any pre-prompt chatter are
    drained automatically so callers only ever see the cleaned response
    body for the command they issued.
    """

    def __init__(self, config: Union[OpenOCDConfig, None] = None) -> None:
        self.config: OpenOCDConfig = config or OpenOCDConfig()
        self._sock: Union[socket.socket, None] = None

    # -- connection lifecycle -------------------------------------------------

    @property
    def connected(self) -> bool:
        """Whether the underlying socket is currently open."""
        return self._sock is not None

    def connect(self) -> None:
        """Open the socket and consume the OpenOCD banner.

        Subsequent calls are no-ops while the socket stays alive.

        Raises:
            ConnectionError: If the OpenOCD daemon cannot be reached.
            TimeoutError: If the banner does not appear within
                ``config.default_timeout`` seconds.
        """
        if self._sock is not None:
            return
        try:
            sock = socket.create_connection(
                (self.config.host, self.config.port),
                timeout=self.config.default_timeout,
            )
        except OSError as exc:
            raise ConnectionError(
                f"Unable to reach OpenOCD at {self.config.host}:{self.config.port}: {exc}"
            ) from exc
        self._sock = sock
        # Drain the banner up to the first prompt so future commands see only
        # their own output.
        try:
            self._read_until_prompt(self.config.default_timeout)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        """Close the underlying socket if it is open."""
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                log.debug("Ignored error while closing OpenOCD socket", exc_info=True)

    def __enter__(self) -> OpenOCDTransport:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- IO -------------------------------------------------------------------

    def _read_until_prompt(self, timeout: int) -> str:
        if self._sock is None:
            raise RuntimeError("OpenOCDTransport is not connected")
        prompt_bytes = self.config.prompt.encode(self.config.encoding)
        deadline = time.monotonic() + timeout
        buffer = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for OpenOCD prompt after {timeout}s"
                )
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout as exc:
                raise TimeoutError(f"Timed out reading from OpenOCD: {exc}") from exc
            if not chunk:
                raise ConnectionError("OpenOCD closed the connection")
            buffer.extend(chunk)
            if buffer.endswith(prompt_bytes):
                break
        return buffer.decode(self.config.encoding, errors="replace")

    def _clean_response(self, raw: str, cmd: str) -> str:
        text = raw
        if text.endswith(self.config.prompt):
            text = text[: -len(self.config.prompt)]
        # Some OpenOCD builds echo the command back; strip it if present.
        for echo in (cmd + "\r\n", cmd + "\n", cmd):
            if text.startswith(echo):
                text = text[len(echo) :]
                break
        return text.strip()

    def execute_command(self, cmd: str, timeout: int = 5) -> str:
        """Send ``cmd`` to OpenOCD and return the cleaned response text.

        The transport connects on first use, sends ``cmd`` followed by a
        newline, and reads bytes until OpenOCD emits its ``> `` prompt. Both
        the trailing prompt and any echoed command line are stripped before
        the response is returned.

        Args:
            cmd: The OpenOCD command to send (without a trailing newline).
            timeout: Maximum seconds to wait for the prompt before raising
                :class:`TimeoutError`.

        Returns:
            The response body stripped of the prompt and surrounding
            whitespace.

        Raises:
            ConnectionError: If the daemon cannot be reached or drops the
                connection mid-read.
            TimeoutError: If OpenOCD does not return a prompt in time.
        """
        self.connect()
        if self._sock is None:
            raise RuntimeError("OpenOCDTransport is not connected")
        payload = (cmd + "\n").encode(self.config.encoding)
        self._sock.sendall(payload)
        raw = self._read_until_prompt(timeout)
        return self._clean_response(raw, cmd)


# ---------------------------------------------------------------------------
# Cartridge
# ---------------------------------------------------------------------------


_INSTALL_HINT: Final[str] = (
    "OpenOCD binary not found on PATH. Install it with "
    "`apt install openocd` (Debian/Ubuntu), `brew install openocd` (macOS), "
    "or build from source: https://openocd.org/."
)


def _raise_if_error(response: str, command: str) -> None:
    if _ERROR_LINE.search(response):
        raise OpenOCDError(
            f"OpenOCD reported an error for `{command}`: {response.strip()}"
        )


class JTAGCartridge:
    """Agentic JTAG operations driven through OpenOCD.

    The cartridge composes an :class:`OpenOCDTransport` with a
    :class:`~wintermute.utils.blob_manager.WorkspaceManager` so that bulk
    artefacts (for example, firmware dumps) bypass the LLM context window
    entirely and instead surface as compact descriptors.

    Each public method is strictly typed and carries a Google-style docstring
    so that :func:`wintermute.ai.utils.tool_factory.function_to_tool` can
    expose it to the AI as a JSON-schema tool.
    """

    def __init__(
        self,
        transport: Union[OpenOCDTransport, None] = None,
        workspace: Union[WorkspaceManager, None] = None,
    ) -> None:
        if transport is None:
            if not _check_openocd_installed():
                raise RuntimeError(_INSTALL_HINT)
            transport = OpenOCDTransport()
        self.transport: OpenOCDTransport = transport
        self.workspace: WorkspaceManager = workspace or get_default_workspace()

    # -- core control --------------------------------------------------------

    def halt_core(self) -> bool:
        """Halt the target CPU at its current instruction.

        Sends OpenOCD's ``halt`` command, which stops execution and lets the
        debugger inspect or modify state. Useful before reading registers,
        dumping memory, or single-stepping.

        Returns:
            ``True`` if OpenOCD acknowledged the halt without an error line.

        Raises:
            OpenOCDError: If OpenOCD's response contains an ``Error:`` line.
            ConnectionError: If the transport cannot reach the daemon.
            TimeoutError: If the daemon does not respond in time.
        """
        response = self.transport.execute_command("halt")
        _raise_if_error(response, "halt")
        return True

    def resume_core(self) -> bool:
        """Resume execution of a previously-halted target.

        Sends OpenOCD's ``resume`` command. Pair with :meth:`halt_core` when
        you need a temporary debug window.

        Returns:
            ``True`` if OpenOCD acknowledged the resume without an error.

        Raises:
            OpenOCDError: If OpenOCD's response contains an ``Error:`` line.
            ConnectionError: If the transport cannot reach the daemon.
            TimeoutError: If the daemon does not respond in time.
        """
        response = self.transport.execute_command("resume")
        _raise_if_error(response, "resume")
        return True

    # -- introspection -------------------------------------------------------

    def read_registers(self) -> Dict[str, str]:
        """Read every general-purpose register from the halted target.

        Sends OpenOCD's ``reg`` command, which prints one register per line in
        the form ``(<idx>) <name> (/<bits>): 0x<value>``. The output is
        parsed into a flat ``{name: hex_value}`` mapping suitable for
        downstream JSON serialisation.

        Returns:
            A dictionary mapping each register name (e.g. ``"r0"``,
            ``"pc"``) to its hex-encoded value (e.g. ``"0x08000123"``).

        Raises:
            OpenOCDError: If OpenOCD reports an error in its response.
            ConnectionError: If the transport cannot reach the daemon.
            TimeoutError: If the daemon does not respond in time.
        """
        response = self.transport.execute_command("reg")
        _raise_if_error(response, "reg")
        registers: Dict[str, str] = {}
        for match in _REGISTER_LINE.finditer(response):
            registers[match.group("name")] = match.group("value")
        return registers

    def read_memory(self, address: str, word_count: int = 1) -> str:
        """Read one or more 32-bit words from target memory.

        Sends OpenOCD's ``mdw <address> <word_count>`` command. The response
        is returned verbatim (with the prompt stripped) so the caller can
        present the original ``ADDR: word0 word1 ...`` layout to the LLM.

        Args:
            address: Target address as a string. Hex literals (``"0x08000000"``)
                and decimal values are both accepted; OpenOCD parses them
                using its standard numeric rules.
            word_count: Number of 32-bit words to read. Must be at least 1.

        Returns:
            The cleaned text body of OpenOCD's response, including the
            address prefix and the space-separated hex words.

        Raises:
            ValueError: If ``word_count`` is less than 1.
            OpenOCDError: If OpenOCD reports an error in its response.
            ConnectionError: If the transport cannot reach the daemon.
            TimeoutError: If the daemon does not respond in time.
        """
        if word_count < 1:
            raise ValueError("word_count must be >= 1")
        cmd = f"mdw {address} {word_count}"
        response = self.transport.execute_command(cmd)
        _raise_if_error(response, cmd)
        return response

    def write_memory(self, address: str, hex_value: str) -> bool:
        """Write a single 32-bit word to target memory.

        Sends OpenOCD's ``mww <address> <hex_value>`` command. The target
        usually needs to be halted via :meth:`halt_core` before the write
        will take effect.

        Args:
            address: Target address (hex or decimal) as a string.
            hex_value: 32-bit value to write, as a hex literal
                (e.g. ``"0xDEADBEEF"``) or decimal string accepted by
                OpenOCD.

        Returns:
            ``True`` if OpenOCD acknowledged the write without an error.

        Raises:
            OpenOCDError: If OpenOCD reports an error in its response.
            ConnectionError: If the transport cannot reach the daemon.
            TimeoutError: If the daemon does not respond in time.
        """
        cmd = f"mww {address} {hex_value}"
        response = self.transport.execute_command(cmd)
        _raise_if_error(response, cmd)
        return True

    # -- bulk operations -----------------------------------------------------

    def dump_firmware(
        self,
        start_address: str,
        size_bytes: int,
        filename: str = "firmware.bin",
    ) -> Dict[str, Union[str, int]]:
        """Dump a memory region directly to disk via OpenOCD's ``dump_image``.

        ``dump_image`` writes the requested range straight to a file inside
        the workspace directory, so multi-megabyte firmware blobs never
        traverse Python memory or the LLM context. Once the dump finishes,
        the file is adopted by the
        :class:`~wintermute.utils.blob_manager.WorkspaceManager` (which
        renames it to a content-addressed slot) and a JSON descriptor is
        returned.

        Args:
            start_address: Memory address to start dumping from, as a string.
                Hex literals (``"0x08000000"``) and decimal values are both
                accepted.
            size_bytes: Number of bytes to dump. Must be positive.
            filename: Hint for the output filename. Only the basename and
                suffix are honoured; the file is renamed to its SHA-256
                digest after the dump completes.

        Returns:
            A descriptor dictionary with the keys ``file_path``, ``size_bytes``,
            ``sha256``, and ``type`` (``"binary_blob"``).

        Raises:
            ValueError: If ``size_bytes`` is less than 1.
            OpenOCDError: If ``dump_image`` reports an error.
            RuntimeError: If OpenOCD claims success but the expected file
                is missing.
            ConnectionError: If the transport cannot reach the daemon.
            TimeoutError: If the daemon does not respond in time.
        """
        if size_bytes < 1:
            raise ValueError("size_bytes must be >= 1")

        # Stream the dump into the workspace root so the eventual rename in
        # WorkspaceManager.register_file stays on a single filesystem.
        workspace_root = self.workspace.root
        workspace_root.mkdir(parents=True, exist_ok=True)
        safe_basename = Path(filename).name or "firmware.bin"
        suffix = Path(safe_basename).suffix or ".bin"
        temp_path = workspace_root / f".pending-{os.getpid()}-{safe_basename}"

        # Use TCL braces to keep the path verbatim (handles spaces, etc.)
        quoted_path = "{" + str(temp_path) + "}"
        cmd = f"dump_image {quoted_path} {start_address} {size_bytes}"

        # Scale the timeout with payload size: real JTAG dumps clock in at
        # ~50-200 KiB/s depending on adapter, so a 1 MiB dump can easily
        # exceed the default 5 s window. 10s baseline + 1s per 64KiB.
        timeout = max(
            self.transport.config.default_timeout,
            10 + size_bytes // (64 * 1024),
        )

        try:
            response = self.transport.execute_command(cmd, timeout=timeout)
        except Exception:
            # Don't leave a partial file lying around.
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

        try:
            _raise_if_error(response, cmd)
            if not temp_path.is_file():
                raise RuntimeError(
                    f"OpenOCD reported success but {temp_path} is missing. "
                    f"Response was: {response!r}"
                )
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
    "JTAGCartridge",
    "OpenOCDConfig",
    "OpenOCDError",
    "OpenOCDTransport",
    "_check_openocd_installed",
]
