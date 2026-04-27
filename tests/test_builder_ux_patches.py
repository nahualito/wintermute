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
from typing import Iterator

import pytest
from prompt_toolkit import HTML
from rich.console import Console

from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.WintermuteConsole import WintermuteConsole


@pytest.fixture()
def console() -> Iterator[WintermuteConsole]:
    c = WintermuteConsole()
    c.rich_console = Console(file=io.StringIO(), force_terminal=False, width=200)
    try:
        yield c
    finally:
        for name in (
            "ai_list_test_runs",
            "ai_get_run_details",
            "ai_update_run_status",
            "ai_add_run_note",
        ):
            global_tool_registry.unregister(name)


def _stdout(c: WintermuteConsole) -> str:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    return buf.getvalue()


def _dispatch(c: WintermuteConsole, cmd: str, args: list[str]) -> bool:
    return asyncio.run(c._dispatch_main_commands(cmd, args))


# ---------------------------------------------------------------------------
# Patch 1 — Visible builder context in the prompt
# ---------------------------------------------------------------------------


def test_render_prompt_root_is_bare(console: WintermuteConsole) -> None:
    rendered = console._render_prompt()
    assert isinstance(rendered, HTML)
    assert "[" not in rendered.value


def test_render_prompt_with_sub_menu(console: WintermuteConsole) -> None:
    console.current_context = "cartridges"
    rendered = console._render_prompt()
    assert "[cartridges]" in rendered.value


def test_render_prompt_builder_takes_priority(
    console: WintermuteConsole,
) -> None:
    """Builder stack wins over current_context — the operator must see
    `[build:device]` even if a sub-menu marker is also set."""
    console.current_context = "operation"
    console.cmd_add_enter("device")
    rendered = console._render_prompt()
    assert "[build:device]" in rendered.value
    assert "[operation]" not in rendered.value


def test_render_prompt_nested_builder_shows_innermost(
    console: WintermuteConsole,
) -> None:
    console.cmd_add_enter("device")
    console.cmd_add_enter("uart", parent_list="peripherals")
    rendered = console._render_prompt()
    # The deepest builder is what the operator is actively editing.
    assert "[build:uart]" in rendered.value


def test_render_prompt_builder_disappears_after_back(
    console: WintermuteConsole,
) -> None:
    console.cmd_add_enter("device")
    assert "[build:device]" in console._render_prompt().value
    console.cmd_back()
    assert "[build:device]" not in console._render_prompt().value


# ---------------------------------------------------------------------------
# Patch 2 — `[add]` menu trap (RETIRED)
#
# The generic `add` menu was ripped out by the domain-router overhaul.
# Operators now navigate `[devices]` / `[analysts]` / `[users]` directly
# (covered by `tests/test_domain_routers.py`); the trap-fix tests that
# used to live here no longer have anything to assert against.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Patch 3 — Builder's `add` is locked down
#
# The builder branch was extracted from `run()` into the new
# :meth:`WintermuteConsole._dispatch_builder_command` method so tests
# exercise the real production path instead of duplicating its logic.
# ---------------------------------------------------------------------------


def test_builder_add_unknown_type_emits_error(
    console: WintermuteConsole,
) -> None:
    """The dangerous fallback `cmd_add_enter(args[0])` is gone. Inside a
    `device` builder, `add user ...` must produce a clear error and NOT
    stack an unrelated user builder."""
    console.cmd_add_enter("device")
    pre_stack_depth = len(console.builder_stack)

    handled = console._dispatch_builder_command(
        "add", ["user", "saenri", "Saenri", "saenri@x.com"]
    )

    assert handled is True  # consumed (rejected, not silently dropped)
    out = _stdout(console)
    assert "Cannot add 'user'" in out
    assert "device builder" in out
    # No additional builder was stacked.
    assert len(console.builder_stack) == pre_stack_depth


def test_builder_add_peripheral_still_works(
    console: WintermuteConsole,
) -> None:
    """Locking down the fallback must NOT break the legitimate
    `add peripheral <type>` and `add vulnerability` flows that the
    builder has always supported."""
    console.cmd_add_enter("device")
    handled = console._dispatch_builder_command("add", ["peripheral", "uart"])
    assert handled is True
    assert console.builder_stack[-1].entity_name == "uart"


def test_builder_add_vulnerability_still_works(
    console: WintermuteConsole,
) -> None:
    console.cmd_add_enter("device")
    handled = console._dispatch_builder_command("add", ["vulnerability"])
    assert handled is True
    assert console.builder_stack[-1].entity_name == "vulnerability"


def test_builder_add_unknown_does_not_drop_inline_args(
    console: WintermuteConsole,
) -> None:
    """The original UX bug: inline args silently disappeared. Confirm
    they're flagged in the rejection so the operator sees what they
    typed and can fix it."""
    console.cmd_add_enter("device")
    console._dispatch_builder_command(
        "add", ["analyst", "Alice", "alice", "alice@x.com"]
    )
    out = _stdout(console)
    assert "analyst" in out
    assert "device builder" in out
    # State unchanged — only the device builder remains, no analyst.
    assert len(console.builder_stack) == 1
    assert console.builder_stack[-1].entity_name == "device"


def test_builder_set_still_routes(console: WintermuteConsole) -> None:
    """Sanity check: extracting the builder dispatch into a method
    didn't break the other builder commands."""
    console.cmd_add_enter("device")
    handled = console._dispatch_builder_command("set", ["hostname", "edge-01"])
    assert handled is True
    assert console.builder_stack[-1].properties["hostname"] == "edge-01"


def test_builder_unknown_command_falls_through(
    console: WintermuteConsole,
) -> None:
    """Commands the builder doesn't own (e.g. `mcp`) return False so
    run() can let the global handlers take a crack at them."""
    console.cmd_add_enter("device")
    handled = console._dispatch_builder_command("mcp", ["list"])
    assert handled is False
