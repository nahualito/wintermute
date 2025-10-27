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

import contextlib
import json
import logging
from importlib import import_module
from pathlib import Path
from typing import (
    Any,
    ContextManager,
    Dict,
    Iterator,
    List,
    Optional,
    Protocol,
    Sequence,
    Set,
    cast,
    runtime_checkable,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# --- Load depthcharge dynamically as Any to avoid mypy 'import-untyped' ---
_depthcharge: Any
try:
    _depthcharge = import_module("depthcharge")
except Exception:  # pragma: no cover
    _depthcharge = None

DepthchargeContext: Any = getattr(_depthcharge, "Depthcharge", None)
Console: Any = getattr(_depthcharge, "Console", None)


# -----------------------------------------------------------------------------
# Protocols (so we don't import your Peripheral directly)
# -----------------------------------------------------------------------------
@runtime_checkable
class PeripheralLike(Protocol):
    device: str
    workspace: str

    def add_vulnerability(self, v: Any) -> None: ...
    def log_info(self, msg: str) -> None: ...


# -----------------------------------------------------------------------------
# Dangerous command taxonomy (tune as needed)
# -----------------------------------------------------------------------------
DANGEROUS_CATEGORIES: Dict[str, Set[str]] = {
    "exec": {"go", "bootm", "bootz", "bootefi"},
    "mem": {"md", "mm", "mw", "cmp", "cp", "crc32"},
    "storage_write": {
        "saveenv",
        "fatwrite",
        "ext4write",
        "nand",
        "sf",
        "mmc",
        "ubi",
        "ubifs",
    },
    "net_fetch": {"tftp", "dhcp", "nfs", "wget"},
    "usb_update": {"fastboot", "ums", "usb", "usb_mass_storage"},
    "hw_bus": {"i2c", "gpio", "mdio", "pci", "pcie"},
    "env": {"env", "printenv", "setenv"},
}
ALL_DANGEROUS: Set[str] = set().union(*DANGEROUS_CATEGORIES.values())


# -----------------------------------------------------------------------------
# Helpers: parsing, severity mapping, model builders (import your classes at runtime)
# -----------------------------------------------------------------------------
def _parse_help(help_output: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for raw in (help_output or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("=>"):
            continue
        if " - " in line:
            name, desc = line.split(" - ", 1)
        else:
            parts = line.split()
            name = parts[0] if parts else ""
            desc = " ".join(parts[1:]) if len(parts) > 1 else ""
        if name:
            out.append({"name": name.split()[0], "desc": desc.strip()})
    return out


def _categorize(name: str) -> List[str]:
    return [k for k, s in DANGEROUS_CATEGORIES.items() if name in s]


def _severity_to_risk(sev: str) -> Dict[str, str]:
    s = sev.lower()
    if s == "critical":
        return {"likelihood": "High", "impact": "Critical", "severity": "Critical"}
    if s == "high":
        return {"likelihood": "Medium", "impact": "High", "severity": "High"}
    if s == "medium":
        return {"likelihood": "Medium", "impact": "Medium", "severity": "Medium"}
    if s == "low":
        return {"likelihood": "Low", "impact": "Low", "severity": "Low"}
    return {"likelihood": "Low", "impact": "Low", "severity": "Low"}


def _make_repro_step(
    *,
    title: str,
    description: str,
    tool: str,
    action: str,
    confidence: int,
    arguments: Sequence[str],
    vulnOutput: Optional[str] = None,
) -> Any:
    from wintermute.findings import ReproductionStep  # runtime import

    return ReproductionStep(
        title=title,
        description=description,
        tool=tool,
        action=action,
        confidence=confidence,
        arguments=list(arguments),
        vulnOutput=vulnOutput,
    )


def _make_user_vuln(
    *,
    title: str,
    description: str,
    threat: str,
    severity: str = "Medium",
    cvss: int = 0,
    mitigation_desc: str = "",
    fix_desc: str = "",
    verified: bool = False,
    reproduction_steps: Optional[List[Any]] = None,
) -> Any:
    from wintermute.findings import Vulnerability  # runtime import

    v = Vulnerability(
        title=title,
        description=description,
        threat=threat,
        cvss=cvss,
        mitigation=True,
        fix=True,
        mitigation_desc=mitigation_desc,
        fix_desc=fix_desc,
        verified=verified,
        reproduction_steps=reproduction_steps or [],
    )
    r = _severity_to_risk(severity)
    v.setRisk(likelihood=r["likelihood"], impact=r["impact"], severity=r["severity"])
    return v


# -----------------------------------------------------------------------------
# Depthcharge context opener (typed as ContextManager[Any])
# -----------------------------------------------------------------------------
def _open_dc_context(device: str, timeout: float) -> ContextManager[Any]:
    """
    Prefer `with depthcharge.Depthcharge(console=device, timeout=...) as dc:`.
    Fallback to wrapping Console in a CM. Treat objects as Any to keep mypy calm.
    """
    if DepthchargeContext is not None:
        return cast(
            ContextManager[Any], DepthchargeContext(console=device, timeout=timeout)
        )

    if Console is None:
        raise RuntimeError("Depthcharge is not available")

    console = Console(device=device, timeout=timeout)

    @contextlib.contextmanager
    def _cm() -> Iterator[Any]:
        try:
            yield console
        finally:
            for attr in ("close", "disconnect", "shutdown"):
                fn = getattr(console, attr, None)
                if callable(fn):
                    try:
                        fn()
                    except Exception:
                        pass
                    break

    return _cm()


# -----------------------------------------------------------------------------
# The agent (mypy-clean)
# -----------------------------------------------------------------------------
class DepthchargePeripheralAgent:
    """
    Runs Depthcharge tasks for a provided Peripheral-like object and
    attaches your Vulnerability objects with ReproductionSteps.
    """

    def __init__(
        self, peripheral: PeripheralLike, default_timeout: float = 2.0
    ) -> None:
        self.peripheral: PeripheralLike = peripheral
        self.device: str = getattr(peripheral, "device", "/dev/ttyUSB0:115200")
        self.workspace: Path = Path(getattr(peripheral, "workspace", "./wm_workspace"))
        self.timeout: float = default_timeout
        self.artifacts: Path = self.workspace / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)

    def _run(self, runner: Any, cmd: str) -> str:
        fn = getattr(runner, "run_cmd", None) or getattr(runner, "run_command", None)
        if fn is None:
            raise RuntimeError("No run_cmd/run_command on Depthcharge object")
        out = fn(cmd)
        return str(out) if out is not None else ""

    # ---- Catalog commands + attach vuln -------------------------------------
    def catalog_commands_and_flag(self) -> Dict[str, Any]:
        self.peripheral.log_info(f"[Depthcharge] Cataloging commands ({self.device})")

        with _open_dc_context(self.device, self.timeout) as dc:
            runner: Any = getattr(dc, "console", dc)
            try:
                if hasattr(runner, "interrupt_boot"):
                    runner.interrupt_boot()
            except Exception:
                pass

            try:
                help_out = self._run(runner, "help")
            except Exception:
                help_out = ""

        parsed = _parse_help(help_out)
        catalog: List[Dict[str, Any]] = []
        dangerous: List[str] = []

        for item in parsed:
            name = item["name"]
            desc = item.get("desc", "")
            cats = _categorize(name)
            is_danger = bool(cats or name in ALL_DANGEROUS)
            catalog.append(
                {"name": name, "desc": desc, "categories": cats, "dangerous": is_danger}
            )
            if is_danger:
                dangerous.append(name)

        # Artifact
        out_path = self.artifacts / "command_catalog.json"
        out_path.write_text(
            json.dumps({"device": self.device, "catalog": catalog}, indent=2),
            encoding="utf-8",
        )

        # Vulnerability using your classes
        if dangerous:
            repro = _make_repro_step(
                title="Enumerate U-Boot commands via console",
                description="Run 'help' over the Depthcharge context and parse the output.",
                tool="depthcharge",
                action="help",
                confidence=8,
                arguments=[f"--device={self.device}", "help"],
                vulnOutput=help_out[:2000] if help_out else None,
            )
            v = _make_user_vuln(
                title="Dangerous U-Boot commands are exposed",
                description=(
                    "The following commands were reported by 'help' and categorized as dangerous: "
                    + ", ".join(sorted(set(dangerous)))
                ),
                threat=(
                    "Presence of memory, storage-write, network fetch, and execution commands may allow "
                    "firmware tampering, data exfiltration, or arbitrary code execution via the console."
                ),
                severity="High",
                mitigation_desc=(
                    "Remove unneeded commands at build time (CONFIG_*), restrict/disable UART in production, "
                    "and enforce verified/FIT boot so untrusted payloads cannot execute."
                ),
                reproduction_steps=[repro],
            )
            self.peripheral.add_vulnerability(v)
            self.peripheral.log_info(
                "[Depthcharge] Attached vulnerability: Dangerous commands"
            )
        else:
            self.peripheral.log_info("[Depthcharge] No dangerous commands identified.")

        return {"device": self.device, "catalog": catalog, "artifact": str(out_path)}

    # ---- Dump memory via API + attach vuln ----------------------------------
    def dump_memory_and_attach_vuln(
        self,
        address: int,
        length: int,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        if filename is None:
            filename = f"memory_dump_{address:08X}_{length}.bin"
        out_path: Path = self.artifacts / filename

        with _open_dc_context(self.device, self.timeout) as dc:
            runner: Any = getattr(dc, "console", dc)

            raw: Optional[bytes] = None
            if _depthcharge is not None and hasattr(_depthcharge, "read_memory"):
                try:
                    raw = _depthcharge.read_memory(
                        console=runner, address=address, length=length
                    )
                except Exception:
                    raw = None
            if raw is None and hasattr(runner, "read_memory"):
                try:
                    raw = runner.read_memory(address, length)
                except Exception:
                    raw = None
            if (
                raw is None
                and _depthcharge is not None
                and hasattr(_depthcharge, "Platform")
            ):
                try:
                    platform = _depthcharge.Platform.detect(console=runner)
                    raw = platform.read_memory(address, length)
                except Exception:
                    raw = None

            if raw is None:
                raise RuntimeError("No working Depthcharge memory-read helper found.")

        # Write file (ignore write return int; we return str path explicitly)
        out_path.write_bytes(raw)

        info: Dict[str, Any] = {
            "device": self.device,
            "address": hex(address),
            "length": length,
            "file": str(out_path),
            "size": len(raw),
        }
        (self.artifacts / "dump_info.json").write_text(
            json.dumps(info, indent=2), encoding="utf-8"
        )

        # Vulnerability (your classes) + reproduction step
        repro = _make_repro_step(
            title="Dump memory via Depthcharge API",
            description="Read memory from target address range using Depthcharge context.",
            tool="depthcharge",
            action="read-memory",
            confidence=9,
            arguments=[
                f"--device={self.device}",
                f"--address={hex(address)}",
                f"--length={length}",
            ],
            vulnOutput=f"Dumped {length} bytes from {hex(address)} to {str(out_path)}",
        )
        v = _make_user_vuln(
            title="Raw memory dumping is possible via U-Boot console",
            description=f"Successfully dumped {length} bytes from {hex(address)} into {str(out_path)}.",
            threat=(
                "Reading arbitrary memory from the bootloader can expose sensitive material "
                "(keys, credentials, firmware, configuration) for offline analysis or tampering."
            ),
            severity="Medium",
            mitigation_desc=(
                "Restrict console access; gate memory primitives behind authentication; ensure secrets "
                "are not resident in readable regions; adopt verified boot to resist tampering."
            ),
            reproduction_steps=[repro],
        )
        self.peripheral.add_vulnerability(v)
        self.peripheral.log_info(
            "[Depthcharge] Attached vulnerability: Memory dump permitted"
        )

        return info
