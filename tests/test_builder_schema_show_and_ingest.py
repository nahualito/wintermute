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


# ---------------------------------------------------------------------------
# Patch 1 — Schema-aware show
# ---------------------------------------------------------------------------


def test_builder_show_lists_all_constructor_fields_with_unset(
    console: WintermuteConsole,
) -> None:
    """Empty device builder must enumerate every field with `<unset>` so
    the operator can see what `set` accepts."""
    console.cmd_add_enter("device")
    _reset_stdout(console)
    console.cmd_builder_show()
    out = _stdout(console)

    # Every Device.__init__ parameter must appear by name.
    for field in (
        "hostname",
        "ipaddr",
        "macaddr",
        "operatingsystem",
        "fqdn",
    ):
        assert field in out, f"missing {field!r} in builder show output"

    # Every value column should currently be <unset>.
    assert out.count("<unset>") >= 5

    # The Type column shows the annotation for at least the simple ones.
    assert "str" in out


def test_builder_show_includes_type_column_header(
    console: WintermuteConsole,
) -> None:
    console.cmd_add_enter("analyst")
    _reset_stdout(console)
    console.cmd_builder_show()
    out = _stdout(console)
    # Header row contains the new column.
    assert "Property" in out
    assert "Type" in out
    assert "Value" in out


def test_builder_show_renders_set_values(
    console: WintermuteConsole,
) -> None:
    console.cmd_add_enter("analyst")
    console.cmd_builder_set("name", "Foo Bar")
    _reset_stdout(console)
    console.cmd_builder_show()
    out = _stdout(console)

    assert "name" in out
    assert "Foo Bar" in out
    # `userid` and `email` haven't been set yet → still surface as unset.
    assert "userid" in out
    assert "email" in out
    assert "<unset>" in out


def test_builder_show_with_no_class_falls_back(
    console: WintermuteConsole,
) -> None:
    """If a builder is constructed without a class (defensive path), show
    must still render — using whatever properties exist."""
    from wintermute.WintermuteConsole import BuilderContext

    ctx = BuilderContext("custom", entity_class=None)
    ctx.properties["foo"] = "bar"
    console.builder_stack.append(ctx)
    _reset_stdout(console)
    console.cmd_builder_show()
    out = _stdout(console)

    assert "Building: custom" in out
    assert "foo" in out
    assert "bar" in out


def test_builder_show_no_active_builder_warns(
    console: WintermuteConsole,
) -> None:
    """Without an active builder, the method bails with a red warning
    instead of dumping the schema of a non-existent target."""
    console.cmd_builder_show()
    assert "No active builder" in _stdout(console)


# ---------------------------------------------------------------------------
# Patch 2 — Inline-args ingestion
# ---------------------------------------------------------------------------


def test_add_analyst_partial_one_arg_pre_populates(
    console: WintermuteConsole,
) -> None:
    """`add analyst Alice` (1 of 3 required) drops into a builder with
    `name=Alice` already set."""
    console.cmd_add("analyst Alice")
    assert len(console.builder_stack) == 1
    builder = console.builder_stack[-1]
    assert builder.entity_name == "analyst"
    assert builder.properties == {"name": "Alice"}
    assert console.active_operation.analysts == []


def test_add_analyst_partial_two_args_pre_populates(
    console: WintermuteConsole,
) -> None:
    """`add analyst Alice ataylor` (2 of 3) pre-populates name + userid."""
    console.cmd_add("analyst Alice ataylor")
    builder = console.builder_stack[-1]
    assert builder.properties.get("name") == "Alice"
    assert builder.properties.get("userid") == "ataylor"
    assert "email" not in builder.properties
    assert console.active_operation.analysts == []


def test_add_analyst_quoted_partial_arg_survives(
    console: WintermuteConsole,
) -> None:
    """Quoted multi-word names survive shlex during partial-arg ingest."""
    console.cmd_add('analyst "Foo Bar" ataylor')
    builder = console.builder_stack[-1]
    assert builder.properties.get("name") == "Foo Bar"
    assert builder.properties.get("userid") == "ataylor"


def test_add_analyst_all_args_bypasses_builder(
    console: WintermuteConsole,
) -> None:
    """Strict-append fast path stays intact."""
    console.cmd_add("analyst Alice ataylor alice@example.com")
    assert console.builder_stack == []
    analysts = console.active_operation.analysts
    assert len(analysts) == 1
    assert analysts[0].name == "Alice"
    assert "Added analyst" in _stdout(console)


def test_add_device_one_arg_appends(console: WintermuteConsole) -> None:
    """Device only requires hostname; one positional arg is "all required"
    and goes through the strict-append path with the default IP."""
    console.cmd_add("device rasp1")
    assert console.builder_stack == []
    devices = console.active_operation.devices
    assert len(devices) == 1
    assert devices[0].hostname == "rasp1"
    out = _stdout(console)
    assert "Added device" in out
    assert "rasp1" in out


def test_add_device_two_args_appends_with_ip(
    console: WintermuteConsole,
) -> None:
    console.cmd_add("device rasp1 10.0.0.5")
    devices = console.active_operation.devices
    assert len(devices) == 1
    assert devices[0].hostname == "rasp1"


def test_add_user_partial_pre_populates(console: WintermuteConsole) -> None:
    console.cmd_add("user u01 Alice")
    builder = console.builder_stack[-1]
    assert builder.entity_name == "user"
    assert builder.properties.get("uid") == "u01"
    assert builder.properties.get("name") == "Alice"
    assert "email" not in builder.properties


def test_add_too_many_args_rejected(console: WintermuteConsole) -> None:
    """More positionals than the spec defines is a hard error — never
    a silent truncation."""
    console.cmd_add("device rasp1 10.0.0.5 extra-bonus")
    out = _stdout(console)
    assert "Too many args" in out
    # Builder never opened, no device appended.
    assert console.builder_stack == []
    assert console.active_operation.devices == []


def test_add_unknown_entity_falls_through_to_builder(
    console: WintermuteConsole,
) -> None:
    """Entities outside the inline-add table still drop into the legacy
    builder so paths like `add cloudaccount` keep working."""
    console.cmd_add("cloudaccount")
    assert len(console.builder_stack) == 1
    assert console.builder_stack[-1].entity_name == "cloudaccount"


def test_add_service_partial_pre_populates(
    console: WintermuteConsole,
) -> None:
    """Partial `add service` enters a builder with whatever was typed."""
    # Seed a device first so the strict path *would* have a target if all
    # 3 args were given — proves we're really on the partial branch here.
    console.active_operation.addDevice("gw01")
    console.cmd_add("service gw01")
    builder = console.builder_stack[-1]
    assert builder.entity_name == "service"
    assert builder.properties.get("device_hostname") == "gw01"
    # Still nothing attached to the device yet.
    device = console.active_operation.getDeviceByHostname("gw01")
    assert device is not None
    assert device.services == []


def test_add_service_all_args_appends(console: WintermuteConsole) -> None:
    """Strict-append fast path for service still works end-to-end."""
    console.active_operation.addDevice("gw01", ipaddr="10.0.0.1")
    console.cmd_add("service gw01 80 http")
    device = console.active_operation.getDeviceByHostname("gw01")
    assert device is not None
    assert any(s.portNumber == 80 and s.app == "http" for s in device.services)
    assert console.builder_stack == []


def test_inline_specs_include_help_signatures(
    console: WintermuteConsole,
) -> None:
    """Sanity: every advertised entity in the help has a matching inline
    spec so the documented and inline behavior agree."""
    for entity in ("analyst", "device", "user", "service"):
        assert entity in WintermuteConsole._INLINE_ADD_SPECS
        spec = WintermuteConsole._INLINE_ADD_SPECS[entity]
        assert "fields" in spec
        assert "required" in spec
        assert spec["required"] <= len(spec["fields"])
