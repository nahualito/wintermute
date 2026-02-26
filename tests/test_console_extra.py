# -*- coding: utf-8 -*-
from unittest.mock import MagicMock, patch

import pytest
from pytest import MonkeyPatch

from wintermute.findings import Vulnerability
from wintermute.peripherals import UART
from wintermute.WintermuteConsole import (
    WintermuteConsole,
    get_visible_state,
)


@pytest.fixture
def console() -> WintermuteConsole:
    c = WintermuteConsole()
    c.operation.addDevice("host1")
    return c


def test_cmd_operation_enter(console: WintermuteConsole) -> None:
    console.cmd_operation_enter()
    assert console.context_stack[-1] == "operation"


def test_cmd_status_with_data(console: WintermuteConsole) -> None:
    dev = console.operation.devices[0]
    dev.addService(portNumber=80, app="http")
    dev.peripherals.append(UART(name="u1"))
    dev.vulnerabilities.append(Vulnerability(title="v1"))
    console.cmd_status()  # smoke test deep tree


def test_cmd_builder_save_service(console: WintermuteConsole) -> None:
    console.cmd_add_enter("service")
    active = console.builder_stack[-1]
    active.properties.update(
        {"portNumber": 443, "app": "https", "device_hostname": "host1"}
    )
    console.cmd_builder_save()
    dev = console.operation.getDeviceByHostname("host1")
    assert dev is not None
    assert any(s.portNumber == 443 for s in dev.services)


def test_cmd_builder_save_nested_vulnerability(console: WintermuteConsole) -> None:
    console.cmd_edit("host1")
    console.cmd_add_enter("vulnerability", parent_list="vulnerabilities")
    console.builder_stack[-1].properties["title"] = "v1"
    console.cmd_builder_save()
    assert len(console.builder_stack[0].properties["vulnerabilities"]) == 1
    console.cmd_builder_save()
    assert len(console.operation.devices[0].vulnerabilities) == 1


def test_cmd_use_run_cartridge(
    console: WintermuteConsole, monkeypatch: MonkeyPatch
) -> None:
    # Use a real module that exists to avoid reload() issues
    import wintermute.core as mock_mod

    with patch("importlib.import_module", return_value=mock_mod):
        console.available_cartridges = ["core"]

        # Mock class finding using monkeypatch instead of direct assignment
        mock_cls = MagicMock()
        monkeypatch.setattr(console, "_find_primary_class", lambda m, n: mock_cls)

        console.cmd_use("core")
        assert console.current_cartridge_name == "core"

        console.cmd_run()
        assert mock_cls.called


def test_cmd_back_cartridge(console: WintermuteConsole) -> None:
    console.current_cartridge_name = "test"
    console.cmd_back()
    assert console.current_cartridge_name is None


def test_cmd_vars_all_types(console: WintermuteConsole) -> None:
    dev = console.operation.devices[0]
    dev.addService(portNumber=22, app="ssh")
    console.cmd_vars("host1")
    console.cmd_vars("host1.ssh")


def test_cmd_builder_set_bool(console: WintermuteConsole) -> None:
    console.cmd_add_enter("device")
    console.cmd_builder_set("verified", "True")
    assert console.builder_stack[-1].properties["verified"] is True
    console.cmd_builder_set("verified", "false")
    assert console.builder_stack[-1].properties["verified"] is False


def test_get_visible_state_pins(console: WintermuteConsole) -> None:
    class Obj:
        def __init__(self) -> None:
            self.pins = {"a": 1}
            self.other = 2
            self._secret = 3

    o = Obj()
    state = get_visible_state(o)
    assert "pins" in state
    assert "other" in state
    assert "_secret" not in state
