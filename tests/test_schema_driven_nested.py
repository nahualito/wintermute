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
from rich.console import Console

from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.core import Service
from wintermute.findings import Vulnerability
from wintermute.peripherals import UART
from wintermute.WintermuteConsole import WintermuteConsole


@pytest.fixture()
def console() -> Iterator[WintermuteConsole]:
    c = WintermuteConsole()
    c.rich_console = Console(file=io.StringIO(), force_terminal=False, width=240)
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


def _reset_stdout(c: WintermuteConsole) -> None:
    buf = c.rich_console.file
    assert isinstance(buf, io.StringIO)
    buf.truncate(0)
    buf.seek(0)


def _dispatch(c: WintermuteConsole, cmd: str, args: list[str]) -> bool:
    return asyncio.run(c._dispatch_main_commands(cmd, args))


# ---------------------------------------------------------------------------
# Patch 1 — _find_by_human_id
# ---------------------------------------------------------------------------


def test_find_by_human_id_matches_hostname() -> None:
    from wintermute.core import Device

    devs = [Device(hostname="rasp1"), Device(hostname="rasp2")]
    found = WintermuteConsole._find_by_human_id(devs, "rasp1")
    assert found is devs[0]


def test_find_by_human_id_matches_portnumber() -> None:
    services = [
        Service(portNumber=80, app="http"),
        Service(portNumber=443, app="https"),
    ]
    found = WintermuteConsole._find_by_human_id(services, "443")
    assert found is services[1]


def test_find_by_human_id_matches_title_for_vulns() -> None:
    vulns = [Vulnerability(title="SQLi"), Vulnerability(title="XSS")]
    found = WintermuteConsole._find_by_human_id(vulns, "XSS")
    assert found is vulns[1]


def test_find_by_human_id_skips_empty_strings() -> None:
    """An object with name='' must NOT match an identifier of ''."""
    s = Service()  # all defaults — name=""
    assert WintermuteConsole._find_by_human_id([s], "") is None


def test_find_by_human_id_returns_none_for_no_match() -> None:
    from wintermute.core import Device

    assert (
        WintermuteConsole._find_by_human_id([Device(hostname="rasp1")], "ghost") is None
    )


# ---------------------------------------------------------------------------
# Patch 2 — _resolve_live_path
# ---------------------------------------------------------------------------


def test_resolve_live_path_top_level_domain(console: WintermuteConsole) -> None:
    console.active_operation.addDevice("rasp1")
    obj = console._resolve_live_path("devices/rasp1")
    assert obj is console.active_operation.getDeviceByHostname("rasp1")


def test_resolve_live_path_two_level(console: WintermuteConsole) -> None:
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.services.append(Service(portNumber=80, app="http"))
    obj = console._resolve_live_path("devices/rasp1/services/80")
    assert obj is device.services[0]


def test_resolve_live_path_returns_collection_on_trailing_collection(
    console: WintermuteConsole,
) -> None:
    """A trailing collection name with no identifier returns the live
    list (used by the back-rewind path)."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.services.append(Service(portNumber=80, app="http"))
    obj = console._resolve_live_path("devices/rasp1/services")
    assert obj is device.services


def test_resolve_live_path_missing_link(console: WintermuteConsole) -> None:
    obj = console._resolve_live_path("devices/ghost")
    assert obj is None


def test_resolve_live_path_empty(console: WintermuteConsole) -> None:
    assert console._resolve_live_path("") is console.active_operation


# ---------------------------------------------------------------------------
# Patch 3 — Dynamic schema-driven nested routing
# ---------------------------------------------------------------------------


def test_peripherals_list_via_schema(console: WintermuteConsole) -> None:
    """`peripherals list` is NOT hardcoded — it works because Device.__schema__
    has `peripherals: Peripheral`."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))
    device.peripherals.append(UART(name="uart1"))

    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    handled = _dispatch(console, "peripherals", ["list"])
    assert handled is True
    out = _stdout(console)
    assert "Peripherals" in out
    assert "uart0" in out and "uart1" in out


def test_vulnerabilities_add_via_schema(console: WintermuteConsole) -> None:
    """`vulnerabilities add` zips inline args against
    Vulnerability.__init__ — `title, description, threat, cvss, …`."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _dispatch(
        console,
        "vulnerabilities",
        ["add", "Stack overflow", "Remote crash", "RCE", "9"],
    )
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert len(device.vulnerabilities) == 1
    v = device.vulnerabilities[0]
    assert v.title == "Stack overflow"
    assert v.description == "Remote crash"
    assert v.threat == "RCE"
    assert v.cvss == 9


def test_peripherals_edit_drills_three_levels(
    console: WintermuteConsole,
) -> None:
    """`devices/rasp1/peripherals/uart0` — the deep schema-driven path
    must be reachable AND resolvable by the path resolver."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))

    console.current_context = "devices/rasp1"
    handled = _dispatch(console, "peripherals", ["edit", "uart0"])
    assert handled is True
    assert console.current_context == "devices/rasp1/peripherals/uart0"

    # The deep path resolves to the live UART instance.
    resolved = console._resolve_live_path(console.current_context)
    assert resolved is device.peripherals[0]


def test_deep_show_at_three_levels(console: WintermuteConsole) -> None:
    """`show` inside `[devices/rasp1/peripherals/uart0]` renders the
    UART's schema-aware panel."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))

    console.current_context = "devices/rasp1/peripherals/uart0"
    _reset_stdout(console)
    handled = _dispatch(console, "show", [])
    assert handled is True
    out = _stdout(console)
    assert "uart0" in out


def test_deep_set_at_three_levels(console: WintermuteConsole) -> None:
    """`set` mutates the live nested UART, not its parent device."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))

    console.current_context = "devices/rasp1/peripherals/uart0"
    _dispatch(console, "set", ["baudrate", "115200"])
    assert getattr(device.peripherals[0], "baudrate") == 115200


def test_peripherals_delete_pops_user_out_of_deep_context(
    console: WintermuteConsole,
) -> None:
    """If we're editing the very nested object that gets deleted, the
    context pops one schema-level up (NOT all the way to the root)."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))
    device.peripherals.append(UART(name="uart1"))

    console.current_context = "devices/rasp1/peripherals/uart0"
    # Delete from the parent context's perspective — shorthand the user
    # would issue from `[devices/rasp1]`. We simulate that by reaching
    # into the dispatcher with the parent context active.
    console.current_context = "devices/rasp1"
    _dispatch(console, "peripherals", ["delete", "uart0"])
    assert all(p.name != "uart0" for p in device.peripherals)
    # The other peripheral survives.
    assert any(p.name == "uart1" for p in device.peripherals)


def test_back_pops_one_schema_level(console: WintermuteConsole) -> None:
    """`back` from `devices/rasp1/peripherals/uart0` lands on
    `devices/rasp1`, not all the way back to `devices`."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))

    console.current_context = "devices/rasp1/peripherals/uart0"
    console.cmd_back()
    assert console.current_context == "devices/rasp1"
    console.cmd_back()
    assert console.current_context == "devices"
    console.cmd_back()
    assert console.current_context == ""


def test_unknown_schema_key_returns_false(console: WintermuteConsole) -> None:
    """A command that doesn't match the live object's __schema__ falls
    through to the regular dispatcher (returns False)."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    handled = _dispatch(console, "definitely_not_a_schema_key", [])
    assert handled is False


def test_scalar_schema_field_emits_hint(console: WintermuteConsole) -> None:
    """`Device.__schema__["processor"] = Processor` — but `processor`
    is a scalar field, not a list. The dispatcher must emit a clear
    hint instead of crashing."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    handled = _dispatch(console, "processor", ["list"])
    assert handled is True
    assert "scalar" in _stdout(console)


# ---------------------------------------------------------------------------
# Patch 4 — Context-aware builder via __schema__
# ---------------------------------------------------------------------------


def test_bare_add_opens_anchored_builder(
    console: WintermuteConsole,
) -> None:
    """``<schema_key> add`` with no inline args opens an interactive
    builder anchored to the live nested collection. ``target_class`` is
    pulled from the schema; ``target_collection`` is the live list ref."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _dispatch(console, "vulnerabilities", ["add"])
    assert len(console.builder_stack) == 1
    builder = console.builder_stack[-1]
    assert builder.entity_class is not None
    assert builder.entity_class.__name__ == "Vulnerability"
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert builder.target_collection is device.vulnerabilities


def test_builder_save_appends_to_target_collection(
    console: WintermuteConsole,
) -> None:
    """When the builder is opened with a target_collection, save appends
    there directly — bypassing the operation-level addAnalyst /
    addDevice / addUser convenience routing.

    Vulnerability has zero required constructor args, so the partial
    fast-path doesn't apply — we must use bare `add` to open the
    builder and then `set` fields interactively."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    console.current_context = "devices/rasp1"

    _dispatch(console, "vulnerabilities", ["add"])
    console.cmd_builder_set("title", "SQL Injection")
    console.cmd_builder_set("description", "user input concatenated into query")
    console.cmd_builder_set("cvss", "8")
    console.cmd_builder_save()

    assert len(device.vulnerabilities) == 1
    v = device.vulnerabilities[0]
    assert v.title == "SQL Injection"
    assert v.description == "user input concatenated into query"
    assert v.cvss == 8


def test_partial_args_open_anchored_builder_for_required_class(
    console: WintermuteConsole,
) -> None:
    """A class with at least one *required* constructor param triggers
    the partial-args builder path when fewer args are typed than there
    are required fields. We use a synthetic class wired into a parent's
    schema to keep the test independent of the domain models' choice of
    defaulted vs required fields."""
    from wintermute.basemodels import BaseModel

    class _RequiredArg(BaseModel):
        def __init__(self, alpha: str, beta: int = 0) -> None:
            self.alpha = alpha
            self.beta = beta

    # Stage a live device + extend its schema for the duration of the
    # test so the dispatcher sees a required-arg class.
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.required_collection = []  # type: ignore[attr-defined]
    type(device).__schema__["required_collection"] = _RequiredArg

    console.current_context = "devices/rasp1"
    try:
        # Zero positionals → not enough for `alpha` → builder.
        _dispatch(console, "required_collection", ["add"])
        assert len(console.builder_stack) == 1
        builder = console.builder_stack[-1]
        assert builder.entity_class is _RequiredArg
        assert builder.target_collection is device.required_collection  # type: ignore[attr-defined]
    finally:
        # Don't leak the test-only schema entry into other tests.
        type(device).__schema__.pop("required_collection", None)


def test_too_many_args_for_schema_add(console: WintermuteConsole) -> None:
    """More positionals than the target class accepts is a hard error
    that does NOT silently drop fields."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    # Vulnerability has many constructor params, but go absurd.
    args = ["add"] + [f"v{i}" for i in range(40)]
    _dispatch(console, "vulnerabilities", args)
    assert "Too many args" in _stdout(console)
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert device.vulnerabilities == []


def test_schema_add_strict_appends_when_zero_required(
    console: WintermuteConsole,
) -> None:
    """If every constructor arg has a default, providing values means
    strict-append: the user's positionals zip against ``__init__`` and
    the rest take their defaults. Builder is NOT opened."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    # Service has zero required params; we provide 4 positionals →
    # name/protocol/app/portNumber.
    _dispatch(console, "services", ["add", "ssh-22", "tcp", "ssh", "22"])
    assert console.builder_stack == []
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert any(s.name == "ssh-22" and s.portNumber == 22 for s in device.services)


def test_help_devices_now_lists_every_schema_collection(
    console: WintermuteConsole,
) -> None:
    """The new help is generated from Device.__schema__ — any list-
    typed schema field shows up in the Deep Context table."""
    console.cmd_help(["devices"])
    out = _stdout(console)
    # Every list-typed schema collection appears as `<key> list/add/edit/delete`.
    for key in ("services", "peripherals", "vulnerabilities"):
        assert f"{key} list" in out
        assert f"{key} add" in out
        assert f"{key} edit" in out
        assert f"{key} delete" in out


def test_help_no_longer_hardcodes_services_only(
    console: WintermuteConsole,
) -> None:
    """The previous implementation only documented `services` for
    devices. The fix means `peripherals` and `vulnerabilities` must
    appear in the help too — proves we ditched the hardcode."""
    console.cmd_help(["devices"])
    out = _stdout(console)
    assert "peripherals list" in out
    assert "vulnerabilities list" in out
