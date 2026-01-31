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
import subprocess
from pathlib import Path
from typing import List

from mcp.server.fastmcp import FastMCP

# Initialize the MCP Server
mcp = FastMCP("SurgeonMCP")

# Configuration: Point this to your SURGEON root directory
SURGEON_ROOT = os.getenv("SURGEON_ROOT", "/home/nahual/projects/HAL/SURGEON")
FIRMWARE_DIR = Path(SURGEON_ROOT) / "firmware"


def _run_command(command: List[str], cwd: str = SURGEON_ROOT) -> str:
    """Helper to run shell commands and return output."""
    try:
        result = subprocess.run(
            command, cwd=cwd, check=True, capture_output=True, text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {' '.join(command)}\nstderr: {e.stderr}\nstdout: {e.stdout}"


@mcp.tool()
async def list_firmware() -> str:
    """
    Lists available firmware projects in the SURGEON firmware directory.
    Useful for the AI to know what targets are available.
    """
    if not FIRMWARE_DIR.exists():
        return "Error: Firmware directory not found."

    projects = [f.name for f in FIRMWARE_DIR.iterdir() if f.is_dir()]
    return json.dumps(projects, indent=2)


@mcp.tool()
async def analyze_firmware(
    firmware_subpath: str, script_type: str = "basic_blocks"
) -> str:
    """
    Runs Ghidra analysis scripts on the target firmware to extract CFG or Symbols.

    Args:
        firmware_subpath: Relative path to firmware inside the 'firmware' folder (e.g., 'p2im/cnc').
        script_type: Either 'basic_blocks' or 'symbols'.
    """
    # Note: In a real deployment, this would trigger the docker/ghidrathon-entrypoint.sh
    # mapped to the specific script. This is a simplified wrapper around the manual step.

    script_map = {
        "basic_blocks": "src/ghidrathon/basic_blocks.py",
        "symbols": "src/ghidra_scripts/get_symbols.py",  # Hypothetical script based on file list
    }

    if script_type not in script_map:
        return f"Unknown script type: {script_type}. Options: basic_blocks, symbols"

    # Construct the command to run the analyzer container
    # This assumes the user has set up a helper script or directly calls docker
    # For this example, we wrap the 'make' command if a specific target exists,
    # or fall back to a direct docker run command pattern used in SURGEON.

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{SURGEON_ROOT}:/surgeon",
        "ghidrathon",  # Assumes you built the helper image
        "python3",
        script_map[script_type],
        f"/surgeon/firmware/{firmware_subpath}",
    ]

    return _run_command(cmd)


@mcp.tool()
async def create_hook_skeleton(
    firmware_name: str, peripheral_name: str, address_base: str
) -> str:
    """
    Creates a C file skeleton for a new peripheral hook in src/runtime/handlers.

    Args:
        firmware_name: Name of the firmware folder (e.g., 'my_radio').
        peripheral_name: Name of the peripheral (e.g., 'uart_custom').
        address_base: Hex string of the base address (e.g., '0x40001000').
    """
    handler_dir = Path(SURGEON_ROOT) / "src" / "runtime" / "handlers" / firmware_name
    handler_dir.mkdir(parents=True, exist_ok=True)

    file_path = handler_dir / f"{peripheral_name}.c"

    c_content = f"""
#include "surgeon/emu_handler.h"
#include <stdio.h>

// Hook for {peripheral_name} at {address_base}

bool {peripheral_name}_read_hook(struct emu_state *state, uint32_t pc, uint32_t addr, uint32_t *val, uint32_t size) {{
    printf("[{peripheral_name}] Read access at 0x%08x\\n", addr);
    *val = 0; // Default return 0
    return true;
}}

bool {peripheral_name}_write_hook(struct emu_state *state, uint32_t pc, uint32_t addr, uint32_t val, uint32_t size) {{
    printf("[{peripheral_name}] Write access at 0x%08x: 0x%08x\\n", addr, val);
    return true;
}}

// TODO: Register this hook in your config.yaml or main handler registry
    """

    with open(file_path, "w") as f:
        f.write(c_content)

    return f"Created hook skeleton at {file_path}. Please implement specific logic and register in config."


@mcp.tool()
async def build_instrumented_firmware(firmware_subpath: str) -> str:
    """
    Runs the SURGEON build process (Autogen -> Compile Runtime -> Rewrite Binary).

    Args:
        firmware_subpath: Relative path (e.g., 'p2im/cnc').
    """
    # SURGEON uses a Makefile at the root
    cmd = ["make", "build", f"FIRMWARE={firmware_subpath}"]
    return _run_command(cmd)


@mcp.tool()
async def start_fuzzing(firmware_subpath: str, duration_seconds: int = 86400) -> str:
    """
    Starts the AFL++ fuzzing campaign in a Docker container.

    Args:
        firmware_subpath: Relative path (e.g., 'p2im/cnc').
        duration_seconds: How long to run (default 24h). Note: SURGEON defaults to 24h in Makefile.
    """
    # We use run-fuzz target from the Makefile
    cmd = ["make", "run-fuzz", f"FIRMWARE={firmware_subpath}"]

    # We run this async/detached in a real scenario, but for MCP we returns the startup log
    return _run_command(cmd)


@mcp.tool()
async def check_fuzzing_status(container_name: str) -> str:
    """
    Checks the logs or status of a running fuzzing container.
    """
    cmd = ["docker", "logs", "--tail", "20", container_name]
    return _run_command(cmd)


if __name__ == "__main__":
    mcp.run()
