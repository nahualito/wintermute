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
# Patch 1 — `add` is gone
# ---------------------------------------------------------------------------


def test_legacy_add_no_longer_dispatched(console: WintermuteConsole) -> None:
    """Bare `add` and `add <type>` must NOT be handled by the dispatcher
    anymore — the contract is now `devices`/`analysts`/`users` + `add`."""
    assert _dispatch(console, "add", []) is False
    assert _dispatch(console, "add", ["device"]) is False


def test_help_no_longer_routes_add_topic(console: WintermuteConsole) -> None:
    """`help add` must NOT render a dedicated sub-help — the topic was
    retired alongside the `[add]` menu."""
    console.cmd_help(["add"])
    out = _stdout(console)
    # The new domain blocks have a "— Operation Data" subtitle. The
    # retired `add` block had "— Populate Workspace". Confirm we no
    # longer see the retired subtitle.
    assert "— Populate Workspace" not in out


# ---------------------------------------------------------------------------
# Patch 2 — Top-level domain routers
# ---------------------------------------------------------------------------


def test_dispatcher_devices_sets_context(console: WintermuteConsole) -> None:
    assert _dispatch(console, "devices", []) is True
    assert console.current_context == "devices"


def test_dispatcher_analysts_sets_context(console: WintermuteConsole) -> None:
    assert _dispatch(console, "analysts", []) is True
    assert console.current_context == "analysts"


def test_dispatcher_users_sets_context(console: WintermuteConsole) -> None:
    assert _dispatch(console, "users", []) is True
    assert console.current_context == "users"


def test_devices_list_renders_table(console: WintermuteConsole) -> None:
    console.active_operation.addDevice("rasp1", ipaddr="10.0.0.5")
    console.active_operation.addDevice("rasp2", ipaddr="10.0.0.6")
    _reset_stdout(console)
    console.cmd_domain("devices", ["list"])
    out = _stdout(console)
    assert "Devices" in out
    assert "rasp1" in out
    assert "rasp2" in out


def test_devices_list_empty_state(console: WintermuteConsole) -> None:
    console.cmd_domain("devices", ["list"])
    out = _stdout(console)
    assert "Devices" in out
    assert "none" in out


def test_devices_add_with_all_args_appends(console: WintermuteConsole) -> None:
    """Inside `[devices]`, `add rasp1 10.0.0.5` round-trips through
    cmd_add → _inline_append and lands on active_operation."""
    console.current_context = "devices"
    handled = _dispatch(console, "add", ["rasp1", "10.0.0.5"])
    assert handled is True
    devices = console.active_operation.devices
    assert any(d.hostname == "rasp1" for d in devices)


def test_analysts_add_partial_drops_into_builder(
    console: WintermuteConsole,
) -> None:
    """`analysts add Alice` (1 of 3) goes to the builder pre-populated."""
    _dispatch(console, "analysts", ["add", "Alice"])
    assert len(console.builder_stack) == 1
    builder = console.builder_stack[-1]
    assert builder.entity_name == "analyst"
    assert builder.properties.get("name") == "Alice"


def test_users_add_with_all_args_appends(console: WintermuteConsole) -> None:
    _dispatch(console, "users", ["add", "u01", "Alice", "alice@example.com"])
    users = console.active_operation.users
    assert any(u.uid == "u01" for u in users)


def test_devices_edit_drills_into_deep_context(
    console: WintermuteConsole,
) -> None:
    """`devices edit rasp1` flips the context to `devices/rasp1`."""
    console.active_operation.addDevice("rasp1")
    _dispatch(console, "devices", ["edit", "rasp1"])
    assert console.current_context == "devices/rasp1"


def test_devices_edit_unknown_id(console: WintermuteConsole) -> None:
    _dispatch(console, "devices", ["edit", "nope"])
    assert "No device with id" in _stdout(console)
    assert console.current_context != "devices/nope"


def test_devices_delete_removes_from_operation(
    console: WintermuteConsole,
) -> None:
    console.active_operation.addDevice("rasp1")
    console.active_operation.addDevice("rasp2")
    _dispatch(console, "devices", ["delete", "rasp1"])
    devices = console.active_operation.devices
    assert all(d.hostname != "rasp1" for d in devices)
    assert any(d.hostname == "rasp2" for d in devices)


def test_devices_delete_unknown_id(console: WintermuteConsole) -> None:
    _dispatch(console, "devices", ["delete", "nope"])
    assert "No device with id" in _stdout(console)


def test_devices_delete_pops_user_out_of_deep_context(
    console: WintermuteConsole,
) -> None:
    """If the operator is editing the very object being deleted, the
    deep context must pop back to the parent domain."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _dispatch(console, "devices", ["delete", "rasp1"])
    assert console.current_context == "devices"


def test_bare_id_drilldown_in_devices_context(
    console: WintermuteConsole,
) -> None:
    """Inside `[devices]`, typing `rasp1` is a muscle-memory shortcut
    for `edit rasp1` (matches the cartridges / testruns pattern)."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices"
    handled = _dispatch(console, "rasp1", [])
    assert handled is True
    assert console.current_context == "devices/rasp1"


def test_unknown_id_in_devices_falls_through(
    console: WintermuteConsole,
) -> None:
    """Bare drilldown only works for *known* hostnames — unknown ids
    return False so the dispatcher can surface `Unknown command`."""
    console.current_context = "devices"
    handled = _dispatch(console, "definitely-not-a-host", [])
    assert handled is False
    assert console.current_context == "devices"


def test_analysts_delete_by_userid(console: WintermuteConsole) -> None:
    console.active_operation.addAnalyst("Alice", "ataylor", "alice@example.com")
    _dispatch(console, "analysts", ["delete", "ataylor"])
    assert console.active_operation.analysts == []


def test_users_delete_by_uid(console: WintermuteConsole) -> None:
    console.active_operation.addUser("u01", "Alice", "alice@example.com", teams=[])
    _dispatch(console, "users", ["delete", "u01"])
    assert console.active_operation.users == []


# ---------------------------------------------------------------------------
# Patch 3 — Deep context editor
# ---------------------------------------------------------------------------


def test_deep_context_show_renders_live_panel(
    console: WintermuteConsole,
) -> None:
    console.active_operation.addDevice("rasp1", ipaddr="10.0.0.5")
    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    handled = _dispatch(console, "show", [])
    assert handled is True
    out = _stdout(console)
    # Title shows the live identifier; schema columns appear; the value
    # column reports the live IP.
    assert "rasp1" in out
    assert "Property" in out and "Type" in out and "Value" in out
    assert "10.0.0.5" in out
    # Unset string fields surface as <unset>.
    assert "<unset>" in out


def test_deep_context_show_includes_services_subtable(
    console: WintermuteConsole,
) -> None:
    """The schema-driven `services add` zips inline args against
    Service.__init__ in declaration order — `name, protocol, app,
    portNumber, …`. To produce a service on port 80 / app=http we have
    to spell that out positionally."""
    console.active_operation.addDevice("rasp1", ipaddr="10.0.0.5")
    console.current_context = "devices/rasp1"
    _dispatch(console, "services", ["add", "web", "tcp", "http", "80"])
    _reset_stdout(console)
    _dispatch(console, "show", [])
    out = _stdout(console)
    # The Property/Type/Value table now lists every nested schema field
    # with a "see sub-table" hint; the dedicated services table follows
    # below it.
    assert "Services" in out
    assert "80" in out and "http" in out


def test_deep_context_set_mutates_live_object(
    console: WintermuteConsole,
) -> None:
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _dispatch(console, "set", ["operatingsystem", "Linux"])
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert device.operatingsystem == "Linux"


def test_deep_context_set_coerces_int(console: WintermuteConsole) -> None:
    """The same int/bool/str inference cmd_builder_set uses applies on
    the live-object path."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    # `dynamic_int_field` doesn't exist on Device — setattr still
    # succeeds and the value is coerced to int.
    _dispatch(console, "set", ["custom_count", "42"])
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert getattr(device, "custom_count") == 42


def test_deep_context_set_missing_args(console: WintermuteConsole) -> None:
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    _dispatch(console, "set", ["onlykey"])
    assert "Usage: set" in _stdout(console)


def test_deep_context_handles_deleted_object(
    console: WintermuteConsole,
) -> None:
    """If the underlying object is removed from beneath the deep
    context, the next command pops back gracefully instead of raising."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    # Yank the device out from underneath.
    console.active_operation.devices.clear()
    handled = _dispatch(console, "show", [])
    assert handled is True
    assert console.current_context == "devices"
    assert "no longer exists" in _stdout(console)


# ---------------------------------------------------------------------------
# Service Management (only inside [devices/<hostname>])
# ---------------------------------------------------------------------------


def test_services_list_in_device_deep_context(
    console: WintermuteConsole,
) -> None:
    from wintermute.core import Service

    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.services.append(Service(portNumber=80, app="http"))
    device.services.append(Service(portNumber=443, app="https"))

    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    _dispatch(console, "services", ["list"])
    out = _stdout(console)
    assert "Services" in out
    assert "80" in out and "http" in out
    assert "443" in out and "https" in out


def test_services_list_empty(console: WintermuteConsole) -> None:
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    _dispatch(console, "services", ["list"])
    assert "No services" in _stdout(console)


def test_services_add_appends(console: WintermuteConsole) -> None:
    """Schema-driven add zips against Service.__init__ in declaration
    order: ``name, protocol, app, portNumber, …``."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _dispatch(console, "services", ["add", "ssh-22", "tcp", "ssh", "22"])
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert any(
        s.name == "ssh-22"
        and s.protocol == "tcp"
        and s.app == "ssh"
        and s.portNumber == 22
        for s in device.services
    )


def test_services_add_partial_drops_into_builder(
    console: WintermuteConsole,
) -> None:
    """Partial inline args open a builder pre-populated with what the
    operator typed, anchored to the device's services list."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    # Service has zero required params (every field has a default), so
    # we exercise the builder via an explicit partial — `services add`
    # with NO args opens an empty builder per the new contract.
    _dispatch(console, "services", ["add"])
    assert len(console.builder_stack) == 1
    builder = console.builder_stack[-1]
    assert builder.entity_class is not None
    assert builder.entity_class.__name__ == "Service"
    # `target_collection` is the device's live services list.
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    assert builder.target_collection is device.services


def test_services_delete_by_port(console: WintermuteConsole) -> None:
    """`_find_by_human_id` hunts ``portNumber`` (among other fields), so
    a port-number identifier still finds the service even though the
    resolver is now generic."""
    from wintermute.core import Service

    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.services.append(Service(portNumber=80, app="http"))
    device.services.append(Service(portNumber=443, app="https"))

    console.current_context = "devices/rasp1"
    _dispatch(console, "services", ["delete", "80"])
    assert all(s.portNumber != 80 for s in device.services)
    assert any(s.portNumber == 443 for s in device.services)


def test_services_delete_unknown_id(console: WintermuteConsole) -> None:
    """The schema dispatcher emits a uniform "No <key> entry matching
    <id>" line for every collection — no more port-specific wording."""
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    _reset_stdout(console)
    _dispatch(console, "services", ["delete", "9999"])
    assert "No services entry matching" in _stdout(console)


def test_services_only_in_devices_context(
    console: WintermuteConsole,
) -> None:
    """`services` is a Device-specific deep command — typing it inside
    `[analysts/<userid>]` must NOT route to the service handler."""
    console.active_operation.addAnalyst("Alice", "ataylor", "alice@example.com")
    console.current_context = "analysts/ataylor"
    handled = _dispatch(console, "services", ["list"])
    # services is unknown in the analyst deep context → False.
    assert handled is False


# ---------------------------------------------------------------------------
# Patch 4 — Global nav + help
# ---------------------------------------------------------------------------


def test_back_pops_devices_deep_to_devices(
    console: WintermuteConsole,
) -> None:
    console.current_context = "devices/rasp1"
    console.cmd_back()
    assert console.current_context == "devices"


def test_back_pops_analysts_deep_to_analysts(
    console: WintermuteConsole,
) -> None:
    console.current_context = "analysts/ataylor"
    console.cmd_back()
    assert console.current_context == "analysts"


def test_back_pops_users_deep_to_users(
    console: WintermuteConsole,
) -> None:
    console.current_context = "users/u01"
    console.cmd_back()
    assert console.current_context == "users"


def test_back_pops_devices_to_root(console: WintermuteConsole) -> None:
    console.current_context = "devices"
    console.cmd_back()
    assert console.current_context == ""


def test_help_devices_lists_subcommands(
    console: WintermuteConsole,
) -> None:
    console.cmd_help(["devices"])
    out = _stdout(console)
    for token in ("list", "add", "edit", "delete"):
        assert token in out
    # Service management is documented in the deep-context block.
    assert "services list" in out
    assert "services add" in out
    assert "services delete" in out


def test_help_analysts_lists_subcommands(
    console: WintermuteConsole,
) -> None:
    console.cmd_help(["analysts"])
    out = _stdout(console)
    for token in ("list", "add", "edit", "delete"):
        assert token in out
    # Services are device-only; must NOT appear in analyst help.
    assert "services list" not in out


def test_help_users_lists_subcommands(console: WintermuteConsole) -> None:
    console.cmd_help(["users"])
    out = _stdout(console)
    for token in ("list", "add", "edit", "delete"):
        assert token in out


def test_help_in_deep_context_renders_parent_help(
    console: WintermuteConsole,
) -> None:
    console.active_operation.addDevice("rasp1")
    console.current_context = "devices/rasp1"
    console.cmd_help([])
    out = _stdout(console)
    # Deep context falls back to the parent domain sub-help — should
    # see the services management table.
    assert "services list" in out


# ---------------------------------------------------------------------------
# Safety bypass still works inside domain contexts
# ---------------------------------------------------------------------------


def test_show_bypasses_domain_routing(console: WintermuteConsole) -> None:
    """Bare `show` inside `[devices]` must reach the operation tree
    handler, not the domain's `list`."""
    console.current_context = "devices"
    _dispatch(console, "show", [])
    out = _stdout(console)
    assert "Operation is currently empty" in out


def test_back_bypasses_domain_routing(console: WintermuteConsole) -> None:
    """`back` is short-circuited by run() before reaching the dispatcher.
    Verify cmd_back's own logic still pops correctly without the
    dispatcher being involved."""
    console.current_context = "devices/rasp1"
    console.cmd_back()
    assert console.current_context == "devices"
