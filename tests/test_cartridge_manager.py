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

from wintermute.ai.tools_runtime import Tool, unregister_tools
from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.cartridges.manager import CartridgeManager
from wintermute.WintermuteConsole import WintermuteConsole

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolate_manager() -> Iterator[None]:
    """Hard-reset the singleton + global tool registry between tests."""
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


# ---------------------------------------------------------------------------
# Singleton + discovery
# ---------------------------------------------------------------------------


def test_singleton_returns_same_instance() -> None:
    a = CartridgeManager()
    b = CartridgeManager()
    assert a is b


def test_list_available_finds_real_cartridges() -> None:
    mgr = CartridgeManager()
    available = set(mgr.list_available())
    assert {"tpm20", "jtag", "firmware_analysis"}.issubset(available)
    assert "manager" not in available
    assert "__init__" not in available


# ---------------------------------------------------------------------------
# Load / unload
# ---------------------------------------------------------------------------


def test_load_firmware_analysis_registers_tools() -> None:
    mgr = CartridgeManager()
    assert mgr.load("firmware_analysis") is True

    instance = mgr.get("firmware_analysis")
    assert type(instance).__name__ == "FirmwareAnalysisCartridge"

    tool_names = mgr.tool_names_for("firmware_analysis")
    assert {
        "analyze_entropy",
        "scan_for_secrets",
        "extract_strings",
        "find_base_address",
    } <= set(tool_names)
    for name in tool_names:
        assert name in global_tool_registry._tools


def test_load_is_idempotent() -> None:
    mgr = CartridgeManager()
    mgr.load("firmware_analysis")
    pre_count = len(global_tool_registry._tools)
    assert mgr.load("firmware_analysis") is False
    assert len(global_tool_registry._tools) == pre_count


def test_unload_removes_tools() -> None:
    mgr = CartridgeManager()
    mgr.load("firmware_analysis")
    tool_names = mgr.tool_names_for("firmware_analysis")
    assert tool_names

    assert mgr.unload("firmware_analysis") is True
    assert "firmware_analysis" not in mgr.list_loaded()
    for name in tool_names:
        assert name not in global_tool_registry._tools


def test_unload_unknown_returns_false() -> None:
    assert CartridgeManager().unload("nonexistent") is False


def test_load_unknown_module_raises() -> None:
    with pytest.raises(ModuleNotFoundError):
        CartridgeManager().load("definitely_not_a_cartridge")


def test_load_wraps_constructor_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the constructor raises, load() must wrap it cleanly and not leave
    a half-initialised entry in loaded_cartridges."""
    from wintermute.cartridges import firmware_analysis

    def _boom(self: object) -> None:
        raise RuntimeError("constructor exploded")

    # Patch only __init__ so suffix-based class detection still resolves
    # to FirmwareAnalysisCartridge.
    monkeypatch.setattr(firmware_analysis.FirmwareAnalysisCartridge, "__init__", _boom)
    mgr = CartridgeManager()
    with pytest.raises(RuntimeError, match="constructor exploded"):
        mgr.load("firmware_analysis")
    assert "firmware_analysis" not in mgr.list_loaded()


# ---------------------------------------------------------------------------
# unregister_tools direct API
# ---------------------------------------------------------------------------


def test_unregister_tools_count() -> None:
    from wintermute.ai.json_types import JSONObject

    def _stub(args: JSONObject) -> JSONObject:
        return {"result": True}

    fake = Tool(
        name="__test_unreg__",
        input_schema={},
        output_schema={},
        handler=_stub,
        description="test",
    )
    global_tool_registry.register(fake)
    assert "__test_unreg__" in global_tool_registry._tools
    removed = unregister_tools(["__test_unreg__", "does_not_exist"])
    assert removed == 1
    assert "__test_unreg__" not in global_tool_registry._tools


# ---------------------------------------------------------------------------
# Console integration: cmd_cartridges
# ---------------------------------------------------------------------------


def test_cmd_cartridges_list_emits_both_tables(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["list"])
    out = _stdout(console)
    assert "Available Cartridges" in out
    assert "Loaded Cartridges" in out
    assert "firmware_analysis" in out


def test_cmd_cartridges_load_then_unload(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["load", "firmware_analysis"])
    out = _stdout(console)
    assert "Loaded cartridge" in out
    assert "firmware_analysis" in CartridgeManager().list_loaded()

    _reset_stdout(console)
    console.cmd_cartridges(["unload", "firmware_analysis"])
    out = _stdout(console)
    assert "Unloaded cartridge" in out
    assert "firmware_analysis" not in CartridgeManager().list_loaded()


def test_cmd_cartridges_run_invokes_method(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["load", "firmware_analysis"])

    with tempfile.TemporaryDirectory() as tmp:
        blob = Path(tmp) / "fw.bin"
        blob.write_bytes(b"\x00" * 4096)

        _reset_stdout(console)
        console.cmd_cartridges(
            ["run", "firmware_analysis", "analyze_entropy", str(blob)]
        )
        out = _stdout(console)
        # rich.print(dict) renders the dict literal — confirm core fields.
        assert "overall_entropy" in out
        assert "high_entropy_blocks" in out


def test_cmd_cartridges_run_missing_method(console: WintermuteConsole) -> None:
    """`AttributeError` from getattr must be reported, not raised."""
    console.cmd_cartridges(["load", "firmware_analysis"])
    _reset_stdout(console)
    console.cmd_cartridges(["run", "firmware_analysis", "definitely_not_a_method"])
    out = _stdout(console)
    assert "no method" in out
    assert "definitely_not_a_method" in out


def test_cmd_cartridges_run_private_method_blocked(
    console: WintermuteConsole,
) -> None:
    console.cmd_cartridges(["load", "firmware_analysis"])
    _reset_stdout(console)
    console.cmd_cartridges(["run", "firmware_analysis", "_render_subhelp"])
    out = _stdout(console)
    assert "private" in out


def test_cmd_cartridges_run_unloaded_cartridge(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["run", "firmware_analysis", "analyze_entropy"])
    out = _stdout(console)
    assert "is not loaded" in out


def test_cmd_cartridges_run_coerces_int_argument(console: WintermuteConsole) -> None:
    """`512` must coerce to int via the function's type annotation."""
    console.cmd_cartridges(["load", "firmware_analysis"])

    with tempfile.TemporaryDirectory() as tmp:
        blob = Path(tmp) / "fw.bin"
        blob.write_bytes(b"\x00" * 4096)
        _reset_stdout(console)
        console.cmd_cartridges(
            ["run", "firmware_analysis", "analyze_entropy", str(blob), "512"]
        )
        out = _stdout(console)
        # block_size echoed in the result dict confirms int coercion happened.
        assert "'block_size': 512" in out


def test_cmd_cartridges_load_unknown_module(console: WintermuteConsole) -> None:
    console.cmd_cartridges(["load", "no_such_cart"])
    out = _stdout(console)
    assert "not found" in out


# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------


def test_use_dispatch_no_longer_handled() -> None:
    """The legacy `use` keyword must NOT be picked up by _dispatch_main_commands."""
    c = WintermuteConsole()

    async def _go() -> bool:
        return await c._dispatch_main_commands("use", ["tpm20"])

    handled = asyncio.run(_go())
    assert handled is False


def test_dispatch_cartridges_sets_context() -> None:
    c = WintermuteConsole()

    async def _go() -> None:
        await c._dispatch_main_commands("cartridges", ["list"])

    asyncio.run(_go())
    assert c.current_context == "cartridges"


def test_help_cartridges_subhelp(console: WintermuteConsole) -> None:
    console.cmd_help(["cartridges"])
    out = _stdout(console)
    for token in ("list", "load", "unload", "run"):
        assert token in out


def test_tpm20_no_legacy_do_method() -> None:
    """The cmd2-style `do_tpm20` was ripped out as part of this overhaul."""
    from wintermute.cartridges.tpm20 import tpm20

    assert not hasattr(tpm20, "do_tpm20")
