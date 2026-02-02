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

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from mcp.server.fastmcp import FastMCP

# Initialize
mcp = FastMCP("SurgeonMCP")

# Config
SURGEON_ROOT = Path(os.getenv("SURGEON_ROOT", "/home/nahual/projects/HAL/SURGEON"))
FIRMWARE_DIR = SURGEON_ROOT / "firmware"


def _run(cmd: List[str], cwd: Path = SURGEON_ROOT) -> str:
    try:
        res = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        return f"CMD Failed: {' '.join(cmd)}\nSTDERR: {e.stderr}"


@mcp.tool()
async def create_hook_skeleton(
    firmware_name: str,
    peripheral_name: str,
    address_base: str,
    peripheral_type: str = "GENERIC",
    malicious_snippet: str = "// No malicious payload injected",
) -> str:
    """
    Generates a C-based emulation hook for a specific peripheral type.

    Args:
        firmware_name: Target firmware folder.
        peripheral_name: Name of the peripheral (e.g., 'wifi_chip').
        address_base: Base address hex string (e.g., '0x40001000').
        peripheral_type: One of [UART, WIFI, BLUETOOTH, ETHERNET, USB, PCIE, JTAG, TPM].
        malicious_snippet: C code to inject for fault injection or fuzzing.
                           Example: "*val = 0xFFFFFFFF; // Integer overflow attack"
    """
    handler_dir = Path(SURGEON_ROOT) / "src" / "runtime" / "handlers" / firmware_name
    handler_dir.mkdir(parents=True, exist_ok=True)
    file_path = handler_dir / f"{peripheral_name}.c"

    ptype = peripheral_type.upper()

    # --- 1. Define The Logic Templates (C Code) ---

    if ptype in ["WIFI", "BLUETOOTH", "ZIGBEE"]:
        # SDR MODE: Treat writes as "Transmits" and reads as "Receives"
        body = f"""
    // --- {ptype} SDR Emulation (Radio Abstraction) ---
    uint32_t offset = addr - {address_base};
    
    // Offset 0x00: Status Register
    // Offset 0x04: TX Buffer (Firmware writes here to send)
    // Offset 0x08: RX Buffer (Firmware reads here to receive)
    
    if (offset == 0x04) {{
        printf("[{peripheral_name}] [TX-RADIO] Packet Broadcast: 0x%08x\\n", val);
        // MALICIOUS HOOK: Intercept outbound traffic?
    }}
    else if (offset == 0x08) {{
        // MALICIOUS HOOK: Inject Inbound Radio Attack
        {malicious_snippet}
        
        if (*val == 0) {{
             *val = 0xDEADBEEF; // Default "noise" on the air
        }}
        printf("[{peripheral_name}] [RX-RADIO] Firmware read radio data: 0x%08x\\n", *val);
    }}
    else {{
        *val = 1; // Always Ready status
    }}
        """

    elif ptype == "ETHERNET":
        body = f"""
    // --- Ethernet MAC Emulation ---
    uint32_t offset = addr - {address_base};
    
    if (offset == 0x00) {{ // MAC Control Register
        printf("[{peripheral_name}] MAC Config Write: 0x%08x\\n", val);
    }}
    else if (offset >= 0x100 && offset < 0x200) {{ // RX Descriptor Ring
        // MALICIOUS HOOK: Buffer Overflow via huge packet size?
        {malicious_snippet}
        printf("[{peripheral_name}] RX Descriptor Access\\n");
    }}
        """

    elif ptype == "USB":
        body = f"""
    // --- USB Endpoint Emulation ---
    uint32_t offset = addr - {address_base};
    
    // Emulate Endpoint 0 (Control) setup packets
    if (offset == 0x00) {{
        printf("[{peripheral_name}] USB EP0 Setup\\n");
        // MALICIOUS HOOK: Fuzzing USB Descriptor responses
        {malicious_snippet}
    }}
        """

    elif ptype == "JTAG":
        body = f"""
    // --- JTAG TAP Controller Spy ---
    // We don't emulate the chain, we just log the activity to find debug backdoors.
    
    if (val & 0x1) printf("[{peripheral_name}] TMS High\\n");
    if (val & 0x2) printf("[{peripheral_name}] TCK Clock\\n");
    
    // MALICIOUS HOOK: Unlock Debug Interface?
    {malicious_snippet}
        """

    elif ptype == "PCIE":
        body = f"""
    // --- PCIe Config Space ---
    uint32_t offset = addr - {address_base};
    
    // Vendor ID / Device ID at 0x00
    if (offset == 0x00) {{
        *val = 0x80868086; // Fake Intel ID
        printf("[{peripheral_name}] PCIe ID Read\\n");
    }}
    // MALICIOUS HOOK: DMA Attack emulation
    {malicious_snippet}
        """

    else:
        # UART / Generic
        body = f"""
    // --- Generic / UART Emulation ---
    uint32_t offset = addr - {address_base};
    if (offset == 0x04) {{
        printf("%c", (char)(val & 0xFF)); // Print UART output to console
    }}
    // MALICIOUS HOOK: Fault Injection
    {malicious_snippet}
        """

    # --- 2. Construct Final C File ---

    c_content = f"""
/* AUTOMATICALLY GENERATED BY SURGEON AGENT */
#include "surgeon/emu_handler.h"
#include <stdio.h>

// Hook for {peripheral_name} ({ptype}) at {address_base}

bool {peripheral_name}_read_hook(struct emu_state *state, uint32_t pc, uint32_t addr, uint32_t *val, uint32_t size) {{
    {body}
    return true;
}}

bool {peripheral_name}_write_hook(struct emu_state *state, uint32_t pc, uint32_t addr, uint32_t val, uint32_t size) {{
    {body}
    return true;
}}
    """

    with open(file_path, "w") as f:
        f.write(c_content)

    return f"Created {ptype} hook at {file_path} with malicious payload size: {len(malicious_snippet)} bytes."


@mcp.tool()
async def list_firmware_symbols(firmware_subpath: str) -> str:
    """Lists function symbols in an ELF file. Essential for finding hook addresses."""
    elf_path = FIRMWARE_DIR / firmware_subpath
    if not elf_path.exists():
        return "Error: ELF file not found."

    # Try generic nm, then cross-compile nm
    nm_bin = "nm"
    if shutil.which("arm-none-eabi-nm"):
        nm_bin = "arm-none-eabi-nm"

    try:
        # -n: sort numeric, -C: demangle, --defined-only
        output = subprocess.check_output(
            [nm_bin, "-n", "-C", "--defined-only", str(elf_path)], text=True
        )
        symbols = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].upper() in ("T", "t"):
                symbols.append({"addr": f"0x{parts[0]}", "name": " ".join(parts[2:])})
        return (
            json.dumps(symbols[:200], indent=2) + f"\n... ({len(symbols) - 200} more)"
        )
    except Exception as e:
        return f"Error running nm: {e}"


@mcp.tool()
async def write_config_file(rel_path: str, content: str) -> str:
    """Writes a configuration file (like YAML) to the SURGEON directory."""
    full_path = SURGEON_ROOT / rel_path
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return f"Wrote {len(content)} bytes to {rel_path}"
    except Exception as e:
        return f"Error writing file: {e}"


# --- High Level Workflow Tools (From user's server.py) ---


@mcp.tool()
async def build_firmware(firmware_name: str) -> str:
    """Runs 'make build FIRMWARE=name'. Compiles the instrumented binary."""
    return _run(["make", "build", f"FIRMWARE={firmware_name}"])


@mcp.tool()
async def start_fuzzing(firmware_name: str) -> str:
    """Runs 'make run-fuzz FIRMWARE=name'. Starts the AFL++ docker container."""
    # We define a timeout or run detached in production.
    # For now, we return the startup output.
    return _run(["make", "run-fuzz", f"FIRMWARE={firmware_name}"])


@mcp.tool()
async def get_fuzzer_stats(firmware_name: str) -> str:
    """Reads the fuzzer_stats file from the AFL output directory."""
    stats_file = FIRMWARE_DIR / firmware_name / "fuzz_out" / "default" / "fuzzer_stats"
    if not stats_file.exists():
        return "Fuzzer stats not found. Is the fuzzer running?"
    with open(stats_file, "r") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run()
