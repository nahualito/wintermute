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
import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from importlib import import_module
from pathlib import Path
from typing import (
    Any,
    ContextManager,
    Dict,
    Iterator,
    List,
    Optional,
    Pattern,
    Protocol,
    Sequence,
    Tuple,
    cast,
    runtime_checkable,
)

logger = logging.getLogger(__name__)

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
    """A minimal Protocol for Wintermute Peripheral-like objects.

    Attributes:
        device_path (str): Device connection string (e.g., COM port or /dev path).
        workspace (str): Path to the workspace directory.
        name (str): Name of the peripheral/device.
        vulnerabilities (List[Any]): List to store found vulnerabilities.
    """

    device_path: str
    workspace: str
    name: str
    vulnerabilities: List[Any]

    def add_vulnerability(self, v: Any) -> None: ...
    def log_info(self, msg: str) -> None: ...


# -----------------------------------------------------------------------------
# Dangerous command taxonomy (tune as needed)
# -----------------------------------------------------------------------------
CATEGORY_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    ("boot", ("boot", "bootm", "booti", "bootz", "boota", "pxe", "sysboot", "go")),
    (
        "mem",
        ("md", "mm", "mw", "nm", "cp", "cmp", "random", "unzip", "unlz4", "lzmadec"),
    ),
    ("env", ("env", "printenv", "setenv", "saveenv", "editenv", "showvar", "run")),
    (
        "files",
        (
            "fat",
            "ext2",
            "ext4",
            "save",
            "load",
            "ls",
            "size",
            "fstype",
            "fsuuid",
            "fstypes",
        ),
    ),
    (
        "storage",
        ("mmc", "nand", "nor", "usb", "sata", "part", "blkcache", "usbboot", "usb "),
    ),
    ("network", ("tftp", "tftpboot", "dhcp", "nfs", "ping", "net", "pxe")),
    (
        "debug",
        (
            "help",
            "version",
            "bdinfo",
            "coninfo",
            "dm",
            "iminfo",
            "mdio",
            "mii",
            "pci",
            "pinmux",
        ),
    ),
]

# “Danger” rules with weights and human-readable tags.
# We check name + summary + details for these keywords/regexes.
DANGER_RULES: List[Tuple[Pattern[str], int, str]] = [
    # irreversible/flashy stuff
    (
        re.compile(
            r"\b(erase|erase\s+blk|hwpartition|partitioning|write\s+once|protect)\b",
            re.I,
        ),
        5,
        "erase/partition",
    ),
    (re.compile(r"\bhwpartition\b", re.I), 5, "mmc-hwpartition"),
    (re.compile(r"\bflash\b", re.I), 4, "flash"),
    (re.compile(r"\b(saveenv|setenv\s+-f)\b", re.I), 4, "persist-env"),
    (re.compile(r"\b(mm c|nand|nor)\b.*\bwrite\b", re.I), 4, "storage-write"),
    (re.compile(r"\bfatwrite|ext4write|save\b", re.I), 3, "fs-write"),
    # memory / register writes
    (re.compile(r"\b(mw|mm|nm|cp)\b", re.I), 3, "mem-write"),
    # boot / execution control
    (re.compile(r"\b(boot|bootm|booti|bootz|boota|go)\b", re.I), 2, "boot/exec"),
    # raw load/copy into memory (potentially safe but risky depending on context)
    (
        re.compile(r"\b(load[bxs y]?|gzwrite|usb\s+write|tftpboot)\b", re.I),
        2,
        "transfer/write-ish",
    ),
]


# -----------------------------------------------------------------------------
# Data classes to help parse and categorize commands
# -----------------------------------------------------------------------------
@dataclass
class DangerInfo:
    """Information about the danger level of a command.

    Attributes:
        severity (int): Severity level of the command (0 = safe-ish, higher = riskier).
        tags (List[str]): List of tags categorizing the danger.
        reason (str): Short explanation of the danger assessment.
    """

    severity: int = 0  # 0 = safe-ish, higher = riskier
    tags: List[str] = field(default_factory=list)  # e.g., ["mem-write", "flash"]
    reason: str = ""  # short explanation

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d["tags"] is None:
            d["tags"] = []
        return d


@dataclass
class CommandRecord:
    """A record of a Depthcharge command with metadata.

    Attributes:
        name (str): Name of the command.
        summary (str): Brief summary of the command.
        usage (List[str]): List of usage lines for the command.
        details (str): Detailed help text for the command.
        categories (List[str]): Categories assigned to the command.
        danger (DangerInfo): Danger assessment of the command.
    """

    name: str
    summary: str
    usage: List[str]
    details: str
    categories: List[str]
    danger: DangerInfo

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["danger"] = self.danger.to_dict()
        return d


# -----------------------------------------------------------------------------
# Helpers: parsing, severity mapping, model builders (import your classes at runtime)
# -----------------------------------------------------------------------------


def _split_device(dev: str, default_baud: int = 115200) -> tuple[str, int]:
    # Accept "/dev/ttyUSB0:115200" or "COM3:115200"; otherwise return (dev, default_baud)
    if ":" in dev and not dev.startswith("tcp://"):
        port, maybe_baud = dev.rsplit(":", 1)
        try:
            return port, int(maybe_baud)
        except ValueError:
            return dev, default_baud
    return dev, default_baud


USAGE_HEADER_RE: re.Pattern[str] = re.compile(r"^\s*Usage:\s*$", re.I | re.M)


def _extract_usage_lines(details: str) -> List[str]:
    """
    Pull 'Usage:' section from details. Many entries look like:

        <name> - summary

        Usage:
        cmd [args...]
        cmd subcmd ...

    We'll capture consecutive non-empty lines after 'Usage:' blocks until a blank line.
    """
    usage_lines: List[str] = []
    lines = details.splitlines()
    i = 0
    while i < len(lines):
        if USAGE_HEADER_RE.match(lines[i]):
            i += 1
            # collect until blank line or end
            block: List[str] = []
            while i < len(lines) and lines[i].strip() != "":
                # strip leading bullets/tabs but keep content
                block.append(lines[i].strip())
                i += 1
            if block:
                usage_lines.extend(block)
        else:
            i += 1
    # De-duplicate while preserving order
    seen = set()
    unique = []
    for u in usage_lines:
        if u not in seen:
            unique.append(u)
            seen.add(u)
    return unique


def _categorize(name: str, summary: str, details: str) -> List[str]:
    """Categorize a command based on its name, summary, and details.

    Arguments:
        name (str): Command name.
        summary (str): Command summary.
        details (str): Command detailed help text.
    """
    key = f"{name} {summary} {details}".lower()
    cats = []
    for cat, tokens in CATEGORY_RULES:
        if any(tok in key for tok in tokens):
            cats.append(cat)
    if not cats:
        cats = ["uncategorized"]
    return cats


def _assess_danger(name: str, summary: str, details: str) -> DangerInfo:
    """Assess the danger level of a command based on its name, summary, and details.

    Arguments:
        name (str): Command name.
        summary (str): Command summary.
        details (str): Command detailed help text.
    """
    blob = f"{name}\n{summary}\n{details}"
    score = 0
    tags: List[str] = []
    reasons: List[str] = []
    for pat, weight, tag in DANGER_RULES:
        if pat.search(blob):
            score += weight
            tags.append(tag)
            reasons.append(tag)
    # Special-case: explicit mmc sub-commands that are scary
    if name.lower().startswith("mmc"):
        if re.search(r"\b(hwpartition|erase|write|wp)\b", blob, re.I):
            score += 2
            if "mmc-ops" not in tags:
                tags.append("mmc-ops")
                reasons.append("mmc-ops")

    # Clamp / tidy
    if score < 0:
        score = 0
    reason = ", ".join(sorted(set(reasons)))
    return DangerInfo(severity=score, tags=sorted(set(tags)), reason=reason)


def _parse_commands(commands_json: Dict[str, Dict[str, str]]) -> List[CommandRecord]:
    """Convert Depthcharge commands() JSON (like the one you pasted) to CommandRecord list.

    Arguments:
        commands_json (Dict[str, Dict[str, str]]): JSON object from Depthcharge commands().
    """
    out: List[CommandRecord] = []
    for name, payload in commands_json.items():
        if not isinstance(payload, dict):
            # skip unexpected shapes
            continue
        summary = (payload.get("summary") or "").strip()
        details = (payload.get("details") or "").strip()
        usage = _extract_usage_lines(details)
        cats = _categorize(name, summary, details)
        danger = _assess_danger(name, summary, details)
        out.append(
            CommandRecord(
                name=name,
                summary=summary,
                usage=usage,
                details=details,
                categories=cats,
                danger=danger,
            )
        )
    # Sort by name for stable output
    out.sort(key=lambda r: r.name.lower())
    return out


def _severity_to_risk(sev: str) -> Dict[str, str]:
    """Map a severity string to likelihood, impact, and severity levels.

    Arguments:
        sev (str): Severity string (e.g., "Critical", "High", "Medium", "Low").
    """
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
    """Create a ReproductionStep object for a vulnerability."""
    from wintermute.findings import ReproductionStep  # runtime import

    logger.debug(f"Creating ReproductionStep: {title}")
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
    """Create a Vulnerability object for user-reported issues."""
    from wintermute.findings import Vulnerability  # runtime import

    logger.debug(f"Creating Vulnerability: {title} with severity {severity}")
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


def _sha256_file(p: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# -----------------------------------------------------------------------------
# Depthcharge context opener (typed as ContextManager[Any])
# -----------------------------------------------------------------------------
def _open_dc_context(
    device: str, timeout: float, arch: Optional[str], prompt: Optional[str] = "U-Boot> "
) -> ContextManager[Any]:
    """Prefer the official Depthcharge context handle. If the installed version
    does not implement __enter__/__exit__, we wrap it. If Depthcharge is
    unavailable, fall back to Console.

    Arguments:
        device (str): Device connection string.
        timeout (float): Timeout for operations.
        arch (Optional[str]): Architecture string (e.g., "aarch64", "arm", "mips").
        prompt (Optional[str]): Expected prompt string for the console.
    """

    if DepthchargeContext is not None:
        # Try passing arch to ctor (newer Depthcharge), else omit and set later.
        handle: Any
        port, baud = _split_device(device)
        con = Console(device=port, timeout=timeout, baudrate=baud, prompt=prompt)
        try:
            con.interrupt()
        except Exception:
            pass
        try:
            con.discover_prompt()
        except Exception:
            pass
        try:
            kwargs = {}
            if arch is not None:
                kwargs["arch"] = arch
            handle = DepthchargeContext(console=con, timeout=timeout, **kwargs)
        except TypeError:
            handle = DepthchargeContext(console=con, timeout=timeout)

        # If it's already a real context manager, return it directly.
        if hasattr(handle, "__enter__") and hasattr(handle, "__exit__"):
            return cast(ContextManager[Any], handle)

        # Otherwise, wrap it as a context manager and apply arch post-construct.
        @contextlib.contextmanager
        def _cm() -> Iterator[Any]:
            try:
                yield handle
            finally:
                for attr in ("close", "disconnect", "shutdown"):
                    fn = getattr(handle, attr, None)
                    if callable(fn):
                        try:
                            fn()
                        except Exception:
                            pass
                        break

        return _cm()

    # Fallback: Console only
    if Console is None:
        raise RuntimeError("Depthcharge is not available")

    console = Console(device=device, timeout=timeout)

    @contextlib.contextmanager
    def _cm_console() -> Iterator[Any]:
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

    return _cm_console()


@dataclass
class CommandInfo:
    """Information about a Depthcharge command.

    Attributes:
        name (str): Name of the command.
        brief (str): Brief summary of the command.
        help (str): Detailed help text for the command.
        dangerous (bool): Whether the command is considered dangerous.
        categories (List[str]): Categories assigned to the command.
    """

    name: str
    brief: str = ""
    help: str = ""
    dangerous: bool = False
    categories: List[str] = None  # type: ignore[assignment]

    def to_dict(self) -> Dict[Any, Any]:
        d = asdict(self)
        if d.get("categories") is None:
            d["categories"] = []
        return d


# -----------------------------------------------------------------------------
# The agent (mypy-clean)
# -----------------------------------------------------------------------------
class DepthchargePeripheralAgent:
    """
    Runs Depthcharge tasks for a provided Peripheral-like object and
    attaches your Vulnerability objects with ReproductionSteps.

    Example:
        >>> from wintermute.backends.depthcharge import DepthchargePeripheralAgent
        >>> from wintermute.core import Operation, Device
        >>> from wintermute.findings import ReproductionStep, Risk, Vulnerability
        >>> from wintermute.peripherals import UART
        >>> op = Operation()
        >>> dev = Device(hostname="test1", architecture="aarch64")
        >>> test1 = UART(baudrate=115200, comPort="/dev/ttyUSB0")
        >>> test1.to_dict()
        >>> dca = DepthchargePeripheralAgent(test1, arch="aarch64")
        >>> f = dca.catalog_commands_and_flag()
        [*] Expected U-Boot prompt: U-Boot>
        [*] Using default payload base address: ${loadaddr} + 32MiB
        [*] Retrieving command list via "help"
        [*] Reading environment via "printenv"
        [*] Depthcharge payload base (0x01000000) + payload offset (0x02000000) => 0x03000000
        [*] Version: U-Boot 2022.01 (Jan 10 2022 - 18:46:34 +0000)
        [*] Enumerating available MemoryWriter implementations...
        [*]   Available: CpMemoryWriter
        [*]   Available: CRC32MemoryWriter
        [*]   Excluded:  I2CMemoryWriter - Command "i2c" required but not detected.
        [*]   Excluded:  LoadbMemoryWriter - Host program "ckermit" required but not found in PATH.
        [*]   Available: LoadxMemoryWriter
        [*]   Available: LoadyMemoryWriter
        [*]   Available: MmMemoryWriter
        [*]   Available: MwMemoryWriter
        [*]   Available: NmMemoryWriter
        [*] Enumerating available MemoryReader implementations...
        [!]   Excluded:  CpCrashMemoryReader - Operation requires crash or reboot, but opt-in not specified.
        [*]   Available: CRC32MemoryReader
        [!]   Excluded:  GoMemoryReader - Payload deployment+execution opt-in not specified
        [*]   Excluded:  I2CMemoryReader - Command "i2c" required but not detected.
        [*]   Available: ItestMemoryReader
        [*]   Available: MdMemoryReader
        [*]   Available: MmMemoryReader
        [*]   Available: SetexprMemoryReader
        [*] Enumerating available Executor implementations...
        [!]   Excluded:  GoExecutor - Payload deployment+execution opt-in not specified
        [*] Enumerating available RegisterReader implementations...
        [!]   Excluded:  CpCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  CRC32CrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  FDTCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  ItestCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  MdCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  MmCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  NmCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!]   Excluded:  SetexprCrashRegisterReader - Operation requires crash or reboot, but opt-in not specified.
        [!] No default RegisterReader available.
        Running runner.commands(detailed=True) to get help output
        [*] Retrieving detailed command info via "help"
        Parsed 93 commands from help output
    """

    def __init__(
        self,
        peripheral: PeripheralLike,
        default_timeout: float = 2.0,
        arch: Optional[str] = None,
    ) -> None:
        self.peripheral: PeripheralLike = peripheral
        self.device: str = getattr(peripheral, "device_path", "/dev/ttyUSB0:115200")
        self.workspace: Path = Path(getattr(peripheral, "workspace", "./wm_workspace"))
        self.timeout: float = default_timeout
        self.arch: Optional[str] = arch
        self.artifacts: Path = self.workspace / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        logger.info(
            f"Initialized DepthchargePeripheralAgent for device {self.device} with arch {self.arch}"
        )

    def _run(self, runner: Any, cmd: str) -> str:
        fn = getattr(runner, "run_cmd", None) or getattr(runner, "run_command", None)
        if fn is None:
            raise RuntimeError("No run_cmd/run_command on Depthcharge object")
        out = fn(cmd)
        return str(out) if out is not None else ""

    # ---- Catalog commands + attach vuln -------------------------------------
    def catalog_commands_and_flag(self, addVulns: bool = True) -> Dict[str, Any]:
        """Catalog U-Boot commands via Depthcharge and attach vulnerability if dangerous commands found.

        Arguments:
            addVulns (bool): Whether to attach vulnerabilities for dangerous commands.
        """
        logger.debug(f"[Depthcharge] Cataloging commands ({self.device})")

        with _open_dc_context(self.device, self.timeout, self.arch) as dc:
            runner: Any = getattr(dc, "console", dc)
            try:
                if hasattr(runner, "interrupt"):
                    runner.interrupt()
            except Exception:
                pass

            try:
                # help_out = self._run(runner, "help")
                print("Running runner.commands(detailed=True) to get help output")
                help_out = dc.commands(detailed=True)
            except Exception:
                help_out = {}  # ""

        parsed = _parse_commands(help_out)
        print(f"Parsed {len(parsed)} commands from help output")
        logger.info(f"[Depthcharge] Parsed {len(parsed)} commands from help output")

        top = sorted(parsed, key=lambda r: r.danger.severity, reverse=True)[:15]
        for r in top:
            sev = r.danger.severity
            logger.info(
                f"  - {r.name:10s}  sev={sev:2d}  tags={','.join(r.danger.tags)}  :: {r.summary}"
            )

        out_path = self.artifacts / "command_catalog.json"
        out_path.write_text(
            json.dumps(
                {
                    "device": self.device,
                    "commands": [r.to_dict() for r in parsed],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        logger.debug(f"[Depthcharge] Saved command catalog to {str(out_path)}")

        if addVulns and any(r.danger.severity >= 1 for r in parsed):
            repro = _make_repro_step(
                title="Enumerate U-Boot commands via console",
                description="Run depthcharge-inspect and verify the configuration created for commands.",
                tool="depthcharge-inspect",
                action="retrieve command catalog",
                confidence=8,
                arguments=[
                    f"--device={self.device}",
                    f" --arch={self.arch}",
                    f"-c f{self.peripheral.name}.conf",
                ],
                vulnOutput=None,
            )
            v = _make_user_vuln(
                title="Dangerous U-Boot commands are exposed",
                description=(
                    "The following commands were reported by 'help' and categorized as dangerous: "
                    + ", ".join(
                        sorted(set([r.name for r in parsed if r.danger.severity >= 1]))
                    )
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
                verified=True,
            )
            if v not in self.peripheral.vulnerabilities:
                self.peripheral.vulnerabilities.append(v)
            logger.debug("[Depthcharge] Attached vulnerability: Dangerous commands")
        else:
            logger.debug("[Depthcharge] No dangerous commands identified.")

        info: Dict[str, Any] = {
            "device": self.device,
            "artifact": str(out_path),
            "total_commands": len(parsed),
            "dangerous_commands": sum(1 for r in parsed if r.danger.severity >= 1),
        }
        logger.info("[Depthcharge] Command cataloging complete: %s", info)

        return info

    # ---- Dump memory via API + attach vuln ----------------------------------
    def dump_memory_and_attach_vuln(
        self,
        address: int,
        length: int,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dump memory via Depthcharge API and attach vulnerability if successful.

        Arguments:
            address (int): Start address to dump.
            length (int): Number of bytes to dump.
            filename (Optional[str]): Optional filename for the dump artifact.
        """
        if filename is None:
            filename = f"memory_dump_{address:08X}_{length}.bin"
        out_path: Path = self.artifacts / filename
        out_path.parent.mkdir(parents=True, exist_ok=True)

        logger.debug("Opening Depthcharge context to dump memory...")
        with _open_dc_context(self.device, self.timeout, self.arch) as dc:
            # Warm up command table (optional, but surfaces issues early)
            try:
                _ = dc.commands(detailed=False)
            except Exception as e:
                logger.debug("commands(detailed=False) failed (continuing): %s", e)

            wrote_file = False

            # 1) Prefer the high-level file writer (returns None on success)
            if hasattr(dc, "read_memory_to_file"):
                try:
                    dc.read_memory_to_file(address, length, str(out_path))
                    wrote_file = out_path.exists() and out_path.stat().st_size > 0
                    if not wrote_file:
                        logger.warning(
                            "read_memory_to_file completed but no file/empty file at %s",
                            out_path,
                        )
                except Exception as e:
                    logger.debug("read_memory_to_file failed: %s", e)

            # 2) Fallback: read bytes, then write ourselves
            if not wrote_file:
                try:
                    if hasattr(dc, "read_memory"):
                        data: bytes = dc.read_memory(address, length)
                        out_path.write_bytes(data)
                        wrote_file = True
                    else:
                        logger.debug(
                            "Context has no read_memory method; skipping byte-read fallback."
                        )
                except Exception as e:
                    logger.debug("read_memory fallback failed: %s", e)

            if not wrote_file:
                raise RuntimeError("No working Depthcharge memory-read helper found.")

        # Build artifact info using the actual file on disk
        actual_size = out_path.stat().st_size
        info: Dict[str, Any] = {
            "device": self.device,
            "address": hex(address),
            "length_requested": length,
            "artifact": str(out_path),
            "size": actual_size,
        }

        # Optional but useful
        try:
            info["sha256"] = _sha256_file(out_path)
        except Exception as e:
            logger.debug("sha256 calc failed: %s", e)

        (self.artifacts / "dump_info.json").write_text(
            json.dumps(info, indent=2), encoding="utf-8"
        )
        logger.info("Memory dump complete: %s (%d bytes)", out_path, actual_size)

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
        if v not in self.peripheral.vulnerabilities:
            self.peripheral.vulnerabilities.append(v)
        logger.debug("[Depthcharge] Attached vulnerability: Memory dump permitted")

        return info
