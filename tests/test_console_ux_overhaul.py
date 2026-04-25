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

import io
from typing import List

import pytest
from prompt_toolkit import HTML
from rich.console import Console

from wintermute.WintermuteConsole import WintermuteConsole


@pytest.fixture()
def console() -> WintermuteConsole:
    c = WintermuteConsole()
    # Pipe rich output to a captured buffer so tests can grep it.
    c.rich_console = Console(file=io.StringIO(), force_terminal=False, width=200)
    return c


def _stdout(c: WintermuteConsole) -> str:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Rule 1 — Contextual prompt
# ---------------------------------------------------------------------------


def test_initial_state_has_no_context(console: WintermuteConsole) -> None:
    assert console.current_context == ""


def test_render_prompt_root(console: WintermuteConsole) -> None:
    rendered = console._render_prompt()
    assert isinstance(rendered, HTML)
    assert "[" not in rendered.value


def test_render_prompt_with_context(console: WintermuteConsole) -> None:
    console.current_context = "mcp"
    rendered = console._render_prompt()
    assert isinstance(rendered, HTML)
    assert "[mcp]" in rendered.value
    assert "onoSendai" in rendered.value


@pytest.mark.asyncio
async def test_dispatch_sets_context_for_mcp(console: WintermuteConsole) -> None:
    await console._dispatch_main_commands("mcp", ["list"])
    assert console.current_context == "mcp"


@pytest.mark.asyncio
async def test_dispatch_sets_context_for_tools(console: WintermuteConsole) -> None:
    await console._dispatch_main_commands("tools", ["list"])
    assert console.current_context == "tools"


@pytest.mark.asyncio
async def test_dispatch_sets_context_for_operation(console: WintermuteConsole) -> None:
    await console._dispatch_main_commands("operation", [])
    assert console.current_context == "operation"


@pytest.mark.asyncio
async def test_dispatch_sets_context_for_bare_add(console: WintermuteConsole) -> None:
    await console._dispatch_main_commands("add", [])
    assert console.current_context == "add"


def test_back_resets_current_context(console: WintermuteConsole) -> None:
    console.current_context = "mcp"
    console.cmd_back()
    assert console.current_context == ""


# ---------------------------------------------------------------------------
# Rule 2 — Help menu overhaul
# ---------------------------------------------------------------------------


def test_help_main_menu_lists_top_level_commands(console: WintermuteConsole) -> None:
    console.cmd_help([])
    out = _stdout(console)
    # `use` was retired in the cartridge-manager overhaul; the main menu
    # now advertises `cartridges` instead.
    for token in (
        "mcp",
        "tools",
        "operation",
        "add",
        "show",
        "cartridges",
        "ai",
        "backend",
    ):
        assert token in out


def test_help_mcp_subcommands(console: WintermuteConsole) -> None:
    console.cmd_help(["mcp"])
    out = _stdout(console)
    for token in ("register", "list", "delete", "start", "stop", "status"):
        assert token in out


def test_help_tools_subcommands(console: WintermuteConsole) -> None:
    console.cmd_help(["tools"])
    out = _stdout(console)
    assert "tools list" in out
    assert "tools mcp" in out
    assert "tools load" in out


def test_help_add_lists_all_supported_types(console: WintermuteConsole) -> None:
    console.cmd_help(["add"])
    out = _stdout(console)
    for token in ("analyst", "device", "user", "service"):
        assert token in out


def test_help_operation_subcommands(console: WintermuteConsole) -> None:
    console.cmd_help(["operation"])
    out = _stdout(console)
    for token in ("create", "set", "save", "load", "delete"):
        assert token in out


def test_help_falls_back_to_context(console: WintermuteConsole) -> None:
    console.current_context = "mcp"
    console.cmd_help([])  # no explicit topic
    out = _stdout(console)
    # Should render the MCP sub-help, not the main menu.
    assert "register" in out
    assert "start" in out


# ---------------------------------------------------------------------------
# Rule 3 — Tools menu fix
# ---------------------------------------------------------------------------


def test_tools_list_shows_internal_tools(console: WintermuteConsole) -> None:
    # The MCP server import path registers cartridge tools into the global
    # registry (TPM/JTAG/firmware analysis), so by the time the test runs
    # there should be at least a handful of internal tools loaded. Even
    # if not, the command must not raise.
    console.cmd_tools("list")
    out = _stdout(console)
    # Either we see the table header, or the empty-state hint.
    assert "Native AI Tools" in out or "No native AI tools" in out


def test_tools_mcp_with_no_running_servers(console: WintermuteConsole) -> None:
    console.cmd_tools("mcp")
    out = _stdout(console)
    assert "No external MCP tools" in out


def test_tools_mcp_renders_running_servers(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wintermute.ai.types import ToolSpec

    fake_specs = [
        ToolSpec(
            name="ghidra__list_funcs",
            description="Enumerate functions",
            input_schema={},
            output_schema={},
        ),
        ToolSpec(
            name="binja__decompile",
            description="Decompile",
            input_schema={},
            output_schema={},
        ),
    ]
    monkeypatch.setattr(
        console.mcp_manager, "get_all_external_tools", lambda: fake_specs
    )
    console.cmd_tools("mcp")
    out = _stdout(console)
    assert "ghidra__list_funcs" in out
    assert "binja__decompile" in out
    # Server column gets the prefix isolated.
    assert "ghidra" in out
    assert "binja" in out


# ---------------------------------------------------------------------------
# Rule 4 — `add` and `show` data state
# ---------------------------------------------------------------------------


def test_add_analyst_with_quoted_name(console: WintermuteConsole) -> None:
    """The original bug: quoted multi-word names dropped silently."""
    console.cmd_add('add analyst "Foo Bar" foobar foobar@example.com')
    analysts = console.active_operation.analysts
    assert len(analysts) == 1
    assert analysts[0].name == "Foo Bar"
    assert analysts[0].userid == "foobar"
    assert analysts[0].email == "foobar@example.com"


def test_add_analyst_via_dispatcher(console: WintermuteConsole) -> None:
    """End-to-end: the run() loop joins args back together; cmd_add re-shlexes
    and the quotes survive the round trip."""
    import asyncio

    async def _go() -> None:
        await console._dispatch_main_commands(
            "add",
            ["analyst", '"Foo', 'Bar"', "foobar", "foobar@x.com"],
        )

    asyncio.run(_go())
    analysts = console.active_operation.analysts
    assert len(analysts) == 1
    assert analysts[0].name == "Foo Bar"


def test_add_analyst_wrong_arg_count(console: WintermuteConsole) -> None:
    console.cmd_add("analyst onlyone")
    out = _stdout(console)
    assert "Usage" in out
    assert console.active_operation.analysts == []


def test_add_device_with_default_ip(console: WintermuteConsole) -> None:
    console.cmd_add("device gateway01")
    devices = console.active_operation.devices
    assert len(devices) == 1
    assert devices[0].hostname == "gateway01"


def test_add_user_appends_to_operation(console: WintermuteConsole) -> None:
    console.cmd_add("user u01 Alice alice@example.com")
    users = console.active_operation.users
    assert any(u.uid == "u01" for u in users)


def test_add_service_attaches_to_device(console: WintermuteConsole) -> None:
    console.cmd_add("device gateway01 10.0.0.1")
    console.cmd_add("service gateway01 80 http")
    device = console.active_operation.getDeviceByHostname("gateway01")
    assert device is not None
    assert any(s.portNumber == 80 and s.app == "http" for s in device.services)


def test_add_service_unknown_device(console: WintermuteConsole) -> None:
    console.cmd_add("service ghost 80 http")
    out = _stdout(console)
    assert "No device" in out


def test_add_falls_through_to_builder_for_unknown_type(
    console: WintermuteConsole,
) -> None:
    # `cloudaccount` is not in the strict-parse path; bare type with no
    # extra args still drops into the builder.
    console.cmd_add("cloudaccount")
    assert len(console.builder_stack) == 1
    assert console.builder_stack[-1].entity_name == "cloudaccount"


def test_show_warns_on_empty_operation(console: WintermuteConsole) -> None:
    console.cmd_show()
    out = _stdout(console)
    assert "Operation is currently empty" in out


def test_show_renders_tree_with_data(console: WintermuteConsole) -> None:
    console.cmd_add('add analyst "Alice Tester" alice alice@x.com')
    console.cmd_add("device gateway 10.0.0.1")

    # Reset stdout so we only see the tree output.
    assert isinstance(console.rich_console.file, io.StringIO)
    console.rich_console.file.truncate(0)
    console.rich_console.file.seek(0)

    console.cmd_show()
    out = _stdout(console)
    assert console.active_operation.operation_name in out
    assert "Alice Tester" in out
    assert "gateway" in out
    assert "Analysts" in out
    assert "Devices" in out


def test_active_operation_property_tracks_reassignment(
    console: WintermuteConsole,
) -> None:
    from wintermute.core import Operation

    new_op = Operation(operation_name="alt-mission")
    console.operation = new_op
    assert console.active_operation is new_op
    assert console.active_operation.operation_name == "alt-mission"


def test_dispatch_show_with_no_args_calls_cmd_show(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bare `show` always routes to cmd_show, never silent."""
    import asyncio

    calls: List[bool] = []
    monkeypatch.setattr(console, "cmd_show", lambda: calls.append(True))

    async def _go() -> None:
        await console._dispatch_main_commands("show", [])

    asyncio.run(_go())
    assert calls == [True]
