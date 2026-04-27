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
from wintermute.core import Service, TestCase, TestPlan
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


# ---------------------------------------------------------------------------
# _human_label fallback chain
# ---------------------------------------------------------------------------


def test_human_label_prefers_hostname() -> None:
    from wintermute.core import Device

    d = Device(hostname="rasp1")
    assert WintermuteConsole._human_label(d) == "rasp1"


def test_human_label_falls_back_to_title_for_vuln() -> None:
    v = Vulnerability(title="SQLi")
    assert WintermuteConsole._human_label(v) == "SQLi"


def test_human_label_uses_portnumber_when_name_empty() -> None:
    s = Service(portNumber=80, app="http")
    # name="" gets skipped → portNumber wins.
    assert WintermuteConsole._human_label(s) == "80"


def test_human_label_uses_name_when_set() -> None:
    s = Service(name="ssh-22", portNumber=22, app="ssh")
    assert WintermuteConsole._human_label(s) == "ssh-22"


def test_human_label_falls_back_to_typename() -> None:
    class _Anon:
        pass

    assert WintermuteConsole._human_label(_Anon()) == "_Anon"


# ---------------------------------------------------------------------------
# cmd_show — empty-state + headers preserved
# ---------------------------------------------------------------------------


def test_show_empty_operation(console: WintermuteConsole) -> None:
    console.cmd_show()
    assert "Operation is currently empty" in _stdout(console)


def test_show_renders_operation_header(console: WintermuteConsole) -> None:
    console.active_operation.addAnalyst("Alice", "alice", "alice@x.com")
    console.cmd_show()
    out = _stdout(console)
    assert console.active_operation.operation_name in out
    assert "Operation:" in out


def test_show_only_renders_populated_branches(
    console: WintermuteConsole,
) -> None:
    """Empty schema collections must NOT show as branches — the legacy
    "[dim]none[/]" placeholders are gone now that the tree is purely
    schema-driven."""
    console.active_operation.addAnalyst("Alice", "alice", "alice@x.com")
    console.cmd_show()
    out = _stdout(console)
    # Analysts is populated → header appears.
    assert "Analysts" in out
    # Devices / Users / Test_plans / Test_runs are empty → no header.
    for empty_branch in ("Devices", "Users", "Test_plans", "Test_runs"):
        assert empty_branch not in out


# ---------------------------------------------------------------------------
# cmd_show — recursive nesting (the bug that triggered this patch)
# ---------------------------------------------------------------------------


def test_show_surfaces_services_under_devices(
    console: WintermuteConsole,
) -> None:
    """Bug reproducer: services were saving to the model but invisible
    in the global tree because the legacy `cmd_show` only rendered
    Devices and their Peripherals — Services and Vulnerabilities were
    completely missing. The recursive walk fixes that."""
    console.active_operation.addDevice("rasp1", ipaddr="10.0.0.5")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.services.append(Service(name="web", portNumber=80, app="http"))
    device.services.append(Service(name="ssh", portNumber=22, app="ssh"))

    console.cmd_show()
    out = _stdout(console)
    assert "Devices" in out
    assert "rasp1" in out
    assert "Services" in out
    assert "web" in out
    assert "ssh" in out


def test_show_surfaces_vulnerabilities_two_levels_deep(
    console: WintermuteConsole,
) -> None:
    """`Service.__schema__["vulnerabilities"] = Vulnerability` means a
    Service's findings should auto-render as leaves under the Service —
    so a Vulnerability nested inside a Service inside a Device shows up
    in the global tree without `cmd_show` knowing anything specific
    about Services or Vulnerabilities."""
    from wintermute.core import Device

    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None and isinstance(device, Device)
    svc = Service(name="web", portNumber=80, app="http")
    svc.vulnerabilities.append(Vulnerability(title="SQL Injection"))
    svc.vulnerabilities.append(Vulnerability(title="XSS"))
    device.services.append(svc)

    console.cmd_show()
    out = _stdout(console)
    assert "rasp1" in out
    assert "Services" in out
    assert "web" in out
    # The deeply-nested vulns now surface — that was impossible with
    # the legacy hardcoded renderer.
    assert "Vulnerabilities" in out
    assert "SQL Injection" in out
    assert "XSS" in out


def test_show_surfaces_peripherals(console: WintermuteConsole) -> None:
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.peripherals.append(UART(name="uart0"))
    device.peripherals.append(UART(name="uart1"))

    console.cmd_show()
    out = _stdout(console)
    assert "Peripherals" in out
    assert "uart0" in out
    assert "uart1" in out


def test_show_surfaces_vulns_directly_on_device(
    console: WintermuteConsole,
) -> None:
    """Device-level vulnerabilities (not nested under a service) also
    render — same recursion, different path through the schema graph."""
    console.active_operation.addDevice("rasp1")
    device = console.active_operation.getDeviceByHostname("rasp1")
    assert device is not None
    device.vulnerabilities.append(Vulnerability(title="default-creds"))

    console.cmd_show()
    out = _stdout(console)
    assert "Vulnerabilities" in out
    assert "default-creds" in out


def test_show_surfaces_test_plans_and_test_cases(
    console: WintermuteConsole,
) -> None:
    """`Operation.__schema__` includes `test_plans` and `test_runs`. The
    legacy renderer ignored both. Now they walk recursively too."""
    plan = TestPlan(
        code="TP-DEMO",
        name="Demo Plan",
        description="",
        test_cases=[TestCase(code="TC-100", name="Boundary Scan")],
    )
    console.active_operation.addTestPlan(plan)
    console.active_operation.generateTestRuns()

    console.cmd_show()
    out = _stdout(console)
    # TestPlan shows up under the operation; its name is the human label.
    assert "Test_plans" in out
    assert "Demo Plan" in out
    # TestCases live under the plan via TestPlan.__schema__["test_cases"].
    assert "Test_cases" in out
    assert "Boundary Scan" in out


def test_show_skips_scalar_schema_fields(console: WintermuteConsole) -> None:
    """`Device.__schema__` has scalar entries (`processor`, `memory`,
    `architecture`). The recursive walk must skip them silently — we
    must NOT see a `Processor` branch when no processor is set."""
    console.active_operation.addDevice("rasp1")
    console.cmd_show()
    out = _stdout(console)
    # Scalar schema fields are not list-typed — they should never
    # surface as folder-style branches.
    assert "Processor" not in out
    assert "Memory" not in out
    assert "Architecture" not in out


def test_show_renders_no_branch_for_empty_nested_collection(
    console: WintermuteConsole,
) -> None:
    """A device with NO services should not render a "Services" header
    — even if other devices have services."""
    console.active_operation.addDevice("loaded", ipaddr="10.0.0.1")
    console.active_operation.addDevice("bare", ipaddr="10.0.0.2")
    loaded = console.active_operation.getDeviceByHostname("loaded")
    assert loaded is not None
    loaded.services.append(Service(name="web", portNumber=80, app="http"))

    console.cmd_show()
    out = _stdout(console)
    # Both devices show.
    assert "loaded" in out
    assert "bare" in out
    # Services header appears (under "loaded") — bug reproduced + fixed.
    assert "Services" in out
    # Count check: only ONE Services header (the bare device must not
    # have produced a phantom empty branch).
    assert out.count("Services") == 1
