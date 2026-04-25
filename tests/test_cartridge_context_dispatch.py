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

import asyncio
import io
import tempfile
from pathlib import Path
from typing import Iterator

import pytest
from rich.console import Console

from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.tools_runtime import unregister_tools
from wintermute.cartridges.manager import CartridgeManager
from wintermute.WintermuteConsole import WintermuteConsole

# ---------------------------------------------------------------------------
# Fixtures + helpers (mirror the conventions in test_cartridge_manager.py
# so isolation is identical)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolate_manager() -> Iterator[None]:
    snapshot = list(global_tool_registry._tools.keys())
    CartridgeManager.reset_for_tests()
    try:
        yield
    finally:
        CartridgeManager.reset_for_tests()
        added = set(global_tool_registry._tools.keys()) - set(snapshot)
        unregister_tools(added)


@pytest.fixture()
def console() -> WintermuteConsole:
    c = WintermuteConsole()
    c.rich_console = Console(file=io.StringIO(), force_terminal=False, width=200)
    return c


def _stdout(c: WintermuteConsole) -> str:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    return buf.getvalue()


def _reset_stdout(c: WintermuteConsole) -> None:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    buf.truncate(0)
    buf.seek(0)


def _dispatch(c: WintermuteConsole, cmd: str, args: list[str]) -> bool:
    return asyncio.run(c._dispatch_main_commands(cmd, args))


# ---------------------------------------------------------------------------
# Rule 1 — Functional contextual dispatcher
# ---------------------------------------------------------------------------


def test_list_inside_cartridges_context_routes_to_overview(
    console: WintermuteConsole,
) -> None:
    console.current_context = "cartridges"
    handled = _dispatch(console, "list", [])
    assert handled is True
    out = _stdout(console)
    assert "Available Cartridges" in out
    assert "Loaded Cartridges" in out


def test_load_inside_cartridges_context_routes_to_loader(
    console: WintermuteConsole,
) -> None:
    console.current_context = "cartridges"
    handled = _dispatch(console, "load", ["firmware_analysis"])
    assert handled is True
    assert "firmware_analysis" in CartridgeManager().list_loaded()


def test_unload_inside_cartridges_context_routes(
    console: WintermuteConsole,
) -> None:
    CartridgeManager().load("firmware_analysis")
    console.current_context = "cartridges"
    handled = _dispatch(console, "unload", ["firmware_analysis"])
    assert handled is True
    assert "firmware_analysis" not in CartridgeManager().list_loaded()


def test_run_inside_cartridges_context_keeps_explicit_form(
    console: WintermuteConsole,
) -> None:
    """Bare `[cartridges]` still expects `run <cart> <fn>` (the deep-context
    shorthand is reserved for `[cartridges/<name>]`)."""
    CartridgeManager().load("firmware_analysis")
    with tempfile.TemporaryDirectory() as tmp:
        blob = Path(tmp) / "fw.bin"
        blob.write_bytes(b"\x00" * 4096)
        console.current_context = "cartridges"
        handled = _dispatch(
            console,
            "run",
            ["firmware_analysis", "analyze_entropy", str(blob)],
        )
    assert handled is True
    assert "overall_entropy" in _stdout(console)


def test_typing_loaded_cartridge_name_drills_in(
    console: WintermuteConsole,
) -> None:
    CartridgeManager().load("firmware_analysis")
    console.current_context = "cartridges"
    handled = _dispatch(console, "firmware_analysis", [])
    assert handled is True
    assert console.current_context == "cartridges/firmware_analysis"


def test_typing_unknown_name_in_cartridges_falls_through(
    console: WintermuteConsole,
) -> None:
    """`tpm20` typed when tpm20 is NOT loaded must NOT silently descend."""
    console.current_context = "cartridges"
    handled = _dispatch(console, "definitely_not_a_cartridge", [])
    assert handled is False
    assert console.current_context == "cartridges"


def test_deep_context_run_uses_implicit_cartridge_name(
    console: WintermuteConsole,
) -> None:
    """The whole point: `run analyze_entropy <path>` works when the
    cartridge name is implied by the [cartridges/<name>] context."""
    CartridgeManager().load("firmware_analysis")
    console.current_context = "cartridges/firmware_analysis"

    with tempfile.TemporaryDirectory() as tmp:
        blob = Path(tmp) / "fw.bin"
        blob.write_bytes(b"\x00" * 4096)
        handled = _dispatch(console, "run", ["analyze_entropy", str(blob)])
    assert handled is True
    assert "overall_entropy" in _stdout(console)


def test_deep_context_list_renders_function_table(
    console: WintermuteConsole,
) -> None:
    CartridgeManager().load("firmware_analysis")
    console.current_context = "cartridges/firmware_analysis"
    handled = _dispatch(console, "list", [])
    assert handled is True
    out = _stdout(console)
    assert "FirmwareAnalysisCartridge" in out
    # Every public method should show up in the deep-inspection table.
    for fn in (
        "analyze_entropy",
        "scan_for_secrets",
        "extract_strings",
        "find_base_address",
    ):
        assert fn in out


def test_deep_context_unload_pops_back(console: WintermuteConsole) -> None:
    CartridgeManager().load("firmware_analysis")
    console.current_context = "cartridges/firmware_analysis"
    handled = _dispatch(console, "unload", [])
    assert handled is True
    assert console.current_context == "cartridges"
    assert "firmware_analysis" not in CartridgeManager().list_loaded()


# ---------------------------------------------------------------------------
# Rule 2 — Verbose load output
# ---------------------------------------------------------------------------


def test_load_prints_exposed_function_names(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["load", "firmware_analysis"])
    out = _stdout(console)
    assert "Exposed functions" in out
    for fn in (
        "analyze_entropy",
        "scan_for_secrets",
        "extract_strings",
        "find_base_address",
    ):
        assert fn in out


# ---------------------------------------------------------------------------
# Rule 3 — Deep cartridge inspection (`list <name>`)
# ---------------------------------------------------------------------------


def test_cartridges_list_with_name_renders_signatures(
    console: WintermuteConsole,
) -> None:
    CartridgeManager().load("firmware_analysis")
    _reset_stdout(console)
    console.cmd_cartridges(["list", "firmware_analysis"])
    out = _stdout(console)
    assert "FirmwareAnalysisCartridge" in out
    # Function column entries.
    assert "analyze_entropy" in out
    # Signature column should expose the parameter type so the user can
    # see `block_size: int = 256`.
    assert "block_size" in out


def test_cartridges_list_with_unloaded_name_is_helpful(
    console: WintermuteConsole,
) -> None:
    """`list firmware_analysis` without loading first must NOT crash."""
    console.cmd_cartridges(["list", "firmware_analysis"])
    out = _stdout(console)
    assert "available but not loaded" in out


def test_cartridges_list_with_unknown_name(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["list", "no_such_cart"])
    out = _stdout(console)
    assert "not found" in out


# ---------------------------------------------------------------------------
# Rule 4 — Global command safeties
# ---------------------------------------------------------------------------


def test_show_bypasses_contextual_routing(console: WintermuteConsole) -> None:
    """`show` inside `[cartridges]` must reach the operation-tree handler,
    NOT the cartridges-list handler."""
    console.current_context = "cartridges"
    handled = _dispatch(console, "show", [])
    assert handled is True
    out = _stdout(console)
    # Empty operation → tree handler emits the warning sentinel.
    assert "Operation is currently empty" in out
    # The cartridges overview tables must NOT appear.
    assert "Available Cartridges" not in out


def test_status_bypasses_contextual_routing(console: WintermuteConsole) -> None:
    """`status` is short-circuited by run() before reaching the dispatcher,
    so it never sees current_context. cmd_status must work regardless."""
    console.current_context = "cartridges"
    # cmd_status writes to rich_console; we only verify it doesn't raise
    # and doesn't mutate current_context.
    console.cmd_status()
    assert console.current_context == "cartridges"


def test_cmd_back_pops_deep_context_one_level(
    console: WintermuteConsole,
) -> None:
    console.current_context = "cartridges/tpm20"
    console.cmd_back()
    assert console.current_context == "cartridges"


def test_cmd_back_pops_cartridges_to_root(console: WintermuteConsole) -> None:
    console.current_context = "cartridges"
    console.cmd_back()
    assert console.current_context == ""


def test_cmd_back_resets_other_contexts_to_root(
    console: WintermuteConsole,
) -> None:
    """Non-cartridges contexts continue to reset directly to root."""
    console.current_context = "mcp"
    console.cmd_back()
    assert console.current_context == ""

    console.current_context = "tools"
    console.cmd_back()
    assert console.current_context == ""


def test_help_in_deep_context_shows_cartridges_subhelp(
    console: WintermuteConsole,
) -> None:
    """`help` inside `[cartridges/tpm20]` must surface the cartridges
    sub-help, not fall through to a generic root menu."""
    console.current_context = "cartridges/firmware_analysis"
    console.cmd_help([])
    out = _stdout(console)
    for token in ("list", "load", "unload", "run"):
        assert token in out
