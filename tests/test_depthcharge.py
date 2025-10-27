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

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

# ---- helpers: a fake console + CM we can yield from your module ----


class FakeConsole:
    """Minimal surface used by the agent."""

    def __init__(self, help_text: str, mem_blob: bytes):
        self._help_text = help_text
        self._mem_blob = mem_blob

    # agent tries run_cmd, then run_command
    def run_cmd(self, cmd: str) -> str:
        if cmd == "help":
            return self._help_text
        # allow printing env if someone calls it later
        if cmd in {"printenv", "env", "env print"}:
            return "bootdelay=3\n"
        return ""

    def run_command(self, cmd: str) -> str:
        return self.run_cmd(cmd)

    def interrupt_boot(self) -> None:
        # no-op; just to satisfy the agent’s best-effort call
        return

    def read_memory(self, address: int, length: int) -> bytes:
        # Return exactly 'length' bytes, taken from our blob (wrap if short)
        blob = (self._mem_blob * ((length // max(1, len(self._mem_blob))) + 1))[:length]
        return blob


@contextmanager
def fake_dc_context(console: FakeConsole) -> Any:
    # The agent does getattr(dc, "console", dc); pretend we are a Depthcharge ctx
    class _Ctx:
        def __init__(self, c: FakeConsole) -> None:
            self.console = c

    ctx = _Ctx(console)
    yield ctx


# ---- a tiny Peripheral stub that collects vulnerabilities for assertions ----


class DummyPeripheral:
    def __init__(self, device: str, workspace: Path) -> None:
        self.device = device
        self.workspace = str(workspace)
        self._vulns: list[Any] = []
        self._logs: list[str] = []

    def add_vulnerability(self, v: Any) -> None:
        self._vulns.append(v)

    def log_info(self, msg: str) -> None:
        self._logs.append(msg)


# ---- tests ----


def test_catalog_commands_and_flag_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Import your module
    from wintermute.backends import depthcharge as dc_mod

    # Prepare fake help text with a mix of safe + dangerous commands
    help_text = """\
help - print command description/usage
md - memory display
mw - memory write
tftp - TFTP download
env print - print environment
bootm - boot application image from memory
help - show help
"""
    mem_blob = b"\xaa\xbb\xcc\xdd"

    # Monkeypatch the module's context opener to yield our fake ctx/console
    monkeypatch.setattr(
        dc_mod,
        "_open_dc_context",
        lambda device, timeout: fake_dc_context(FakeConsole(help_text, mem_blob)),
        raising=True,
    )

    # Run the agent against our dummy peripheral/workspace
    periph = DummyPeripheral(device="/dev/ttyUSB0:115200", workspace=tmp_path)
    agent = dc_mod.DepthchargePeripheralAgent(peripheral=periph)

    result = agent.catalog_commands_and_flag()

    # Assertions: artifact created, parsed catalog present, vuln recorded
    artifact_path = Path(result["artifact"])
    assert artifact_path.exists(), "command_catalog.json should be written"

    payload = json.loads(artifact_path.read_text())
    names = [c["name"] for c in payload["catalog"]]
    assert "mw" in names and "tftp" in names and "bootm" in names

    # At least one dangerous command should have been flagged
    flagged = [c for c in payload["catalog"] if c["dangerous"]]
    assert flagged, "expected at least one dangerous command flagged"

    # Your Vulnerability object should have been attached
    assert len(periph._vulns) == 1
    vuln = periph._vulns[0]
    # basic sanity checks on your fields
    assert hasattr(vuln, "title")
    assert "Dangerous U-Boot commands" in vuln.title


def test_dump_memory_and_attach_vuln_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wintermute.backends import depthcharge as dc_mod

    help_text = "help - print help\n"
    mem_blob = (
        b"\xde\xad\xbe\xef"  # will be repeated/truncated by FakeConsole.read_memory
    )

    monkeypatch.setattr(
        dc_mod,
        "_open_dc_context",
        lambda device, timeout: fake_dc_context(FakeConsole(help_text, mem_blob)),
        raising=True,
    )

    periph = DummyPeripheral(device="/dev/ttyUSB0:115200", workspace=tmp_path)
    agent = dc_mod.DepthchargePeripheralAgent(peripheral=periph)

    # Execute a small dump so the test runs fast
    out = agent.dump_memory_and_attach_vuln(
        address=0x80000000, length=16, filename="dump.bin"
    )

    # Binary file written with expected size
    dump_file = Path(out["file"])
    assert dump_file.exists()
    assert dump_file.read_bytes() == mem_blob * 4  # 4 * 4 bytes = 16

    # A descriptor json should also exist
    dump_info = json.loads(
        (Path(periph.workspace) / "artifacts" / "dump_info.json").read_text()
    )
    assert dump_info["length"] == 16
    assert dump_info["address"] == hex(0x80000000)

    # A second vulnerability should have been attached
    assert len(periph._vulns) >= 1
    titles = [getattr(v, "title", "") for v in periph._vulns]
    assert any("Memory dump" in t or "Raw memory dumping" in t for t in titles)
