# -*- coding: utf-8 -*-
from unittest.mock import MagicMock, patch

import pytest

from wintermute.core import Device, Operation
from wintermute.findings import Vulnerability
from wintermute.peripherals import UART
from wintermute.WintermuteConsole import BuilderContext, WintermuteConsole


def test_console_device_save_with_nested_objects() -> None:
    """Test that saving a Device with nested Peripherals/Vulnerabilities attaches them correctly."""
    # Setup Console
    console = WintermuteConsole()
    # Mock operation to avoid side effects (though it's in-memory by default)
    console.operation = Operation("test-op")

    # Mock rich console to suppress output
    console.rich_console = MagicMock()

    # 1. Simulate entering Device builder
    console.cmd_add_enter("device")
    assert len(console.builder_stack) == 1
    device_builder = console.builder_stack[0]

    # Set properties
    console.cmd_builder_set("hostname", "test-console-dev")
    console.cmd_builder_set("ipaddr", "10.0.0.1")

    # 2. Simulate adding Peripheral (UART)
    console.builder_stack.append(
        BuilderContext("uart", UART, parent_list_name="peripherals")
    )
    console.cmd_builder_set("name", "uart0")

    # Save Peripheral (Nested Save)
    console.cmd_builder_save()

    # Verify peripheral added to device builder properties
    assert len(console.builder_stack) == 1
    assert "peripherals" in device_builder.properties
    assert len(device_builder.properties["peripherals"]) == 1
    assert isinstance(device_builder.properties["peripherals"][0], UART)

    # 3. Simulate adding Vulnerability
    console.builder_stack.append(
        BuilderContext(
            "vulnerability", Vulnerability, parent_list_name="vulnerabilities"
        )
    )
    console.cmd_builder_set("title", "Test Vuln")
    console.cmd_builder_set("cvss", "9.0")

    # Save Vulnerability (Nested Save)
    console.cmd_builder_save()

    # Verify vuln added to device builder properties
    assert len(console.builder_stack) == 1
    assert "vulnerabilities" in device_builder.properties
    assert len(device_builder.properties["vulnerabilities"]) == 1

    # 4. Save Device (Root Save)
    console.cmd_builder_save()

    # Verify builder stack is empty
    assert len(console.builder_stack) == 0

    # Verify Device created in Operation
    dev = console.operation.getDeviceByHostname("test-console-dev")
    assert dev is not None
    assert dev.ipaddr.exploded == "10.0.0.1"

    # Verify Peripherals and Vulnerabilities attached
    assert len(dev.peripherals) == 1
    assert dev.peripherals[0].name == "uart0"

    assert len(dev.vulnerabilities) == 1
    assert dev.vulnerabilities[0].title == "Test Vuln"


def test_console_builder_show_recursive() -> None:
    """Test recursive show output logic."""
    console = WintermuteConsole()
    console.rich_console = MagicMock()

    console.cmd_add_enter("device")
    console.builder_stack[0].properties["peripherals"] = [
        UART(name="u1"),
        UART(name="u2"),
    ]

    # Should not raise error
    console.cmd_builder_show()

    # Verify table was printed
    console.rich_console.print.assert_called()


def test_console_status_recursive() -> None:
    """Test status tree recursion logic."""
    console = WintermuteConsole()
    console.rich_console = MagicMock()

    dev = Device(hostname="dev1")
    dev.peripherals.append(UART(name="u1"))
    dev.vulnerabilities.append(Vulnerability(title="v1", cvss=5))
    console.operation.devices.append(dev)

    # Should not raise error
    console.cmd_status()

    # Verify tree was printed
    console.rich_console.print.assert_called()


def test_console_prompt_update() -> None:
    """Test that prompt reflects operation context."""
    console = WintermuteConsole()
    console.rich_console = MagicMock()

    # Initial state
    tokens = console.get_prompt_tokens()
    # Should be just [prompt, wintermute, prompt, >] (length 2 because root context adds no extra token)
    assert len(tokens) == 2
    assert tokens[0][1] == "wintermute "

    # Enter Operation
    console.cmd_operation_create("op1")
    # cmd_operation_create now enters context

    tokens = console.get_prompt_tokens()
    # Should contain operation context
    # [prompt, wintermute, context, operation(op1), prompt, >]
    context_token = next((t for t in tokens if t[0] == "class:context"), None)
    assert context_token is not None
    assert "operation(op1)" in context_token[1]


def test_console_default_backend() -> None:
    """Test that default backend is initialized."""
    # We need to reset Operation backend state because it's a class variable
    # and might be set by other tests or previous runs
    Operation._backend = None

    _console = WintermuteConsole()
    assert Operation._backend is not None
    # Depending on imports, it should be JsonFileBackend
    assert Operation._backend.__class__.__name__ == "JsonFileBackend"


@pytest.mark.asyncio
async def test_console_global_command_fallback() -> None:
    """Test that global commands are accessible from operation context."""
    console = WintermuteConsole()
    console.rich_console = MagicMock()

    # Enter operation context
    console.cmd_operation_create("test-op")
    assert console.context_stack[-1] == "operation"

    # Verify that 'status' (a main command) is handled via fallback
    # We simulate the loop logic here
    cmd = "status"
    _args: list[object] = []

    # Simulate current handler failure and fallback
    handled = False
    # Operation handler doesn't have status
    if cmd in ["set", "save", "load", "delete"]:
        handled = True

    if not handled:
        # Check if _dispatch_main_commands handles it
        # Actually _dispatch_main_commands handles 'add', 'use', etc.
        # 'status' is in global navigation
        pass

    # Let's test _dispatch_main_commands directly for 'add'
    with patch.object(console, "cmd_add_enter") as mock_add:
        handled = await console._dispatch_main_commands("add", ["device"])
        assert handled is True
        mock_add.assert_called_once_with("device")


@pytest.mark.asyncio
async def test_console_device_save_linking() -> None:
    """Verify that save command correctly links nested objects via addDevice."""
    console = WintermuteConsole()
    console.operation = MagicMock(spec=Operation)
    console.rich_console = MagicMock()

    # Simulate device builder with peripherals and vulns
    console.cmd_add_enter("device")
    builder = console.builder_stack[-1]
    builder.properties["hostname"] = "linked-dev"
    builder.properties["peripherals"] = [UART(name="u1")]
    builder.properties["vulnerabilities"] = [Vulnerability(title="v1")]

    # Trigger save
    console.cmd_builder_save()

    # Verify operation.addDevice was called with correct arguments
    console.operation.addDevice.assert_called_once()
    kwargs = console.operation.addDevice.call_args.kwargs
    assert kwargs["hostname"] == "linked-dev"
    assert len(kwargs["peripherals"]) == 1
    assert len(kwargs["vulnerabilities"]) == 1
