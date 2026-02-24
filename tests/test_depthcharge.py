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

import importlib
import io
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, cast

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Ensure repo root is on sys.path (robust under hatch/coverage)
# Assuming this file lives at: <repo>/wintermute/tests/test_depthcharge.py
# Then REPO_ROOT = parents[2]
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# ──────────────────────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────────────────────
# Stub ONLY the external 'depthcharge' dependency
# ──────────────────────────────────────────────────────────────────────────────
class _ArchObj:
    supports_64bit_data: bool = True


class FakeConsole:
    def __init__(
        self,
        device: str,
        *,
        baudrate: int = 115200,
        timeout: float = 1.0,
        prompt: Optional[str] = None,
    ) -> None:
        self.device = device
        self.baudrate = baudrate
        self.timeout = timeout
        self.prompt = prompt or "U-Boot> "
        self._buf = io.StringIO()

    def write(self, s: str) -> None:
        self._buf.write(s)

    def interrupt(self, key: str = "\x03") -> None:
        return

    def discover_prompt(self) -> None:
        self.prompt = self.prompt or "U-Boot> "

    def close(self) -> None:
        pass


class FakeDepthcharge:
    def __init__(
        self,
        console: FakeConsole,
        *,
        arch: Optional[str] = None,
        detailed_help: bool = False,
        timeout: Optional[float] = None,
    ) -> None:
        self.console = console
        self.arch = _ArchObj()  # important: not a str
        self._detailed = detailed_help

    def commands(self, *, detailed: bool = False) -> Dict[str, Dict[str, str]]:
        # Shape matches what your parser expects
        if self._detailed or detailed:
            return {
                "md": {
                    "summary": "memory display",
                    "details": "md - memory display\n\nUsage:\nmd [.b, .w] addr [count]\n",
                },
                "mw": {
                    "summary": "memory write (fill)",
                    "details": "mw - memory write\n\nUsage:\nmw [.b, .w] addr value [count]\n",
                },
                "mmc": {
                    "summary": "MMC sub system",
                    "details": "mmc - MMC sub system\n\nUsage:\nmmc write addr blk# cnt\nmmc erase blk# cnt\nmmc read addr blk# cnt\n",
                },
                "help": {
                    "summary": "print help",
                    "details": "help - print command description\n\nUsage:\nhelp\n",
                },
            }
        return {
            "md": {"summary": "memory display", "details": "md - memory display"},
            "mw": {"summary": "memory write (fill)", "details": "mw - memory write"},
        }

    # High-level API (writes file, returns None)
    def read_memory_to_file(
        self, addr: int, size: int, filename: str, **_: Any
    ) -> None:
        Path(filename).write_bytes(b"\xaa" * int(size))
        return None

    # Fallback API (returns bytes)
    def read_memory(self, addr: int, size: int, **_: Any) -> bytes:
        return b"\xbb" * int(size)


# Inject the fake depthcharge module before importing your code
_fake_dc: Any = types.ModuleType("depthcharge")
_fake_dc.Console = FakeConsole
_fake_dc.Depthcharge = FakeDepthcharge
sys.modules["depthcharge"] = _fake_dc


# ──────────────────────────────────────────────────────────────────────────────
# Import your real module under test
# ──────────────────────────────────────────────────────────────────────────────
dc_mod = importlib.import_module("wintermute.backends.depthcharge")


# ──────────────────────────────────────────────────────────────────────────────
# Typed test scaffolding
# ──────────────────────────────────────────────────────────────────────────────
class PeripheralLike(Protocol):
    device_path: str
    workspace: str
    name: str
    vulnerabilities: List[Any]

    def add_vulnerability(self, v: Any) -> None: ...
    def log_info(self, msg: str) -> None: ...


@dataclass
class DummyPeripheral:
    device_path: str = "/dev/ttyUSB0:115200"
    workspace: str = "./wm_workspace_test"
    name: str = "UART0"
    vulnerabilities: List[Any] = field(default_factory=list)

    def add_vulnerability(self, v: Any) -> None:
        self.vulnerabilities.append(v)

    def log_info(self, msg: str) -> None:
        _ = msg  # no-op


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_open_dc_context_arch_not_string(tmp_path: Path) -> None:
    # Ensure context opens and arch is an object, not a stray string
    ctx_cm = cast(Any, getattr(dc_mod, "_open_dc_context"))
    with ctx_cm("/dev/ttyUSB0:115200", 1.0, None) as ctx:
        assert hasattr(ctx, "commands")
        arch = getattr(ctx, "arch", None)
        assert not isinstance(arch, str), "ctx.arch must not be a string"


def test_catalog_commands_and_flag_creates_artifact_and_vuln(tmp_path: Path) -> None:
    dummy = DummyPeripheral(workspace=str(tmp_path))
    Agent = cast(Any, getattr(dc_mod, "DepthchargePeripheralAgent"))
    agent = Agent(peripheral=dummy, default_timeout=0.5, arch=None)

    info = agent.catalog_commands_and_flag(addVulns=True)

    # Info schema + artifact presence
    assert (
        "artifact" in info and "total_commands" in info and "dangerous_commands" in info
    )
    artifact = Path(cast(str, info["artifact"]))
    assert artifact.exists() and artifact.is_file()
    # Parser should see dangerous (mw/mmc) and at least one vuln attached
    assert info["dangerous_commands"] >= 1
    assert len(dummy.vulnerabilities) >= 1


def test_dump_memory_and_attach_vuln_writes_file_and_size(tmp_path: Path) -> None:
    dummy = DummyPeripheral(workspace=str(tmp_path))
    Agent = cast(Any, getattr(dc_mod, "DepthchargePeripheralAgent"))
    agent = Agent(peripheral=dummy, default_timeout=0.5, arch=None)

    length = 0x200
    info = agent.dump_memory_and_attach_vuln(0x3EC00000, length, "mem.bin")
    p = Path(cast(str, info.get("artifact") or info.get("file")))
    assert p.exists() and p.stat().st_size == length
    assert info.get("size") == length
    # Optional hash acceptable if present
    if "sha256" in info:
        sha = cast(str, info["sha256"])
        assert isinstance(sha, str) and len(sha) == 64
    # A vulnerability should be attached
    assert len(dummy.vulnerabilities) >= 1


def test_split_device_accepts_colon_baud() -> None:
    splitter = cast(Any, getattr(dc_mod, "_split_device"))
    port, baud = splitter("/dev/ttyUSB0:230400")
    assert port == "/dev/ttyUSB0" and baud == 230400

    port2, baud2 = splitter("COM3:115200")
    assert port2 == "COM3" and baud2 == 115200

    port3, baud3 = splitter("/dev/ttyUSB0")
    assert port3 == "/dev/ttyUSB0" and baud3 == 115200


def test_parser_danger_scoring_smoke() -> None:
    # Use your parser over a sample that should flag 'mw' and 'mmc'
    parse_fn = cast(
        Any, getattr(dc_mod, "_parse_commands", getattr(dc_mod, "parse_commands", None))
    )
    if parse_fn is None:
        pytest.skip("No parser exposed in module")

    sample: Dict[str, Dict[str, str]] = {
        "mmc": {
            "summary": "MMC sub system",
            "details": "mmc - MMC sub system\n\nUsage:\nmmc write addr blk# cnt\nmmc erase blk# cnt\n",
        },
        "mw": {
            "summary": "memory write (fill)",
            "details": "mw - memory write\n\nUsage:\nmw [.b, .w] addr value [count]\n",
        },
        "md": {
            "summary": "memory display",
            "details": "md - memory display\n\nUsage:\nmd [.b, .w] addr [count]\n",
        },
    }
    records = parse_fn(sample)
    assert isinstance(records, list) and records, "parser must produce a non-empty list"
    by_name = {r.name: r for r in records}
    assert by_name["mw"].danger.severity > 0
    assert by_name["mmc"].danger.severity > 0
    assert by_name["md"].danger.severity == 0
