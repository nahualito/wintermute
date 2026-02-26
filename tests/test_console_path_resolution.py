# -*- coding: utf-8 -*-
"""
Tests for WintermuteConsole path resolution and builder functionality.
"""

from unittest.mock import MagicMock

import pytest
from pytest import CaptureFixture, MonkeyPatch

from wintermute.core import Device, Service
from wintermute.findings import Vulnerability
from wintermute.peripherals import TPM, UART
from wintermute.WintermuteConsole import (
    BuilderContext,
    WintermuteConsole,
    get_visible_state,
)


class TestGetVisibleState:
    """Tests for the get_visible_state helper function."""

    def test_get_visible_state_basic(self) -> None:
        """Test basic state extraction."""
        device = Device(hostname="test-host", ipaddr="192.168.1.1")
        state = get_visible_state(device)
        assert "hostname" in state
        assert state["hostname"] == "test-host"
        assert "ipaddr" in state
        # Convert to string for comparison as Device converts to IPv4Address
        assert str(state["ipaddr"]) == "192.168.1.1"

    def test_get_visible_state_excludes_schema_keys(self) -> None:
        """Test that schema keys are excluded."""
        device = Device(hostname="test-host", ipaddr="192.168.1.1")
        state = get_visible_state(device)
        # __schema__ should not be in the visible state
        assert "__schema__" not in state

    def test_get_visible_state_excludes_private_attrs(self) -> None:
        """Test that private attributes are excluded."""
        device = Device(hostname="test-host", ipaddr="192.168.1.1")
        state = get_visible_state(device)
        # Private attributes should not be in visible state
        for key in state.keys():
            assert not key.startswith("_") or key == "pins"

    def test_get_visible_state_includes_pins(self) -> None:
        """Test that pins attribute is included for visibility."""
        uart = UART(name="uart0", pins={"pin1": "value1", "pin2": "value2"})
        state = get_visible_state(uart)
        assert "pins" in state
        assert state["pins"] == {"pin1": "value1", "pin2": "value2"}

    def test_get_visible_state_with_peripheral(self) -> None:
        """Test state extraction for peripheral."""
        uart = UART(name="uart0")
        state = get_visible_state(uart)
        assert "name" in state
        assert state["name"] == "uart0"


class TestResolvePath:
    """Tests for the _resolve_path method."""

    @pytest.fixture
    def console(self) -> WintermuteConsole:
        """Create a WintermuteConsole instance with test data."""
        console = WintermuteConsole()
        # Create test operation with nested objects
        # Add device with peripherals, services, and vulnerabilities
        console.operation.addDevice(
            hostname="gateway",
            ipaddr="192.168.1.1",
            peripherals=[
                UART(name="uart0"),
                TPM(name="tpm0"),
            ],
            services=[
                Service(portNumber=22, app="ssh"),
            ],
            vulnerabilities=[
                Vulnerability(
                    title="CVE-2024-1234",
                    cvss=9,  # Changed from 9.8 to 9 (int)
                    description="Critical vulnerability",
                ),
            ],
        )
        console.operation.addDevice("server", ipaddr="192.168.1.2")

        # Add user
        console.operation.addUser("admin", "Admin User", "admin@example.com", teams=[])

        # Add AWS account
        console.operation.addAWSAccount("prod", account_id="123456789012")

        return console

    def test_resolve_path_simple_hostname(self, console: WintermuteConsole) -> None:
        """Test resolving a simple hostname."""
        result = console._resolve_path("gateway")
        assert result is not None
        assert result.hostname == "gateway"

    def test_resolve_path_peripheral(self, console: WintermuteConsole) -> None:
        """Test resolving a peripheral path."""
        result = console._resolve_path("gateway.peripherals.uart0")
        assert result is not None
        assert result.name == "uart0"
        assert isinstance(result, UART)

    def test_resolve_path_tpm_peripheral(self, console: WintermuteConsole) -> None:
        """Test resolving a TPM peripheral path."""
        result = console._resolve_path("gateway.peripherals.tpm0")
        assert result is not None
        assert result.name == "tpm0"
        assert isinstance(result, TPM)

    def test_resolve_path_service(self, console: WintermuteConsole) -> None:
        """Test resolving a service path."""
        result = console._resolve_path("gateway.services.ssh")
        assert result is not None
        assert result.app == "ssh"

    def test_resolve_path_vulnerability(self, console: WintermuteConsole) -> None:
        """Test resolving a vulnerability path."""
        result = console._resolve_path("gateway.vulnerabilities.CVE-2024-1234")
        assert result is not None
        assert result.title == "CVE-2024-1234"

    def test_resolve_path_user(self, console: WintermuteConsole) -> None:
        """Test resolving a user path."""
        result = console._resolve_path("admin")
        assert result is not None
        assert result.uid == "admin"

    def test_resolve_path_aws_account(self, console: WintermuteConsole) -> None:
        """Test resolving an AWS account path."""
        result = console._resolve_path("prod")
        assert result is not None
        assert result.name == "prod"

    def test_resolve_path_with_slashes(self, console: WintermuteConsole) -> None:
        """Test resolving path with slashes."""
        result = console._resolve_path("gateway/peripherals/uart0")
        assert result is not None
        assert result.name == "uart0"

    def test_resolve_path_explicit_device_prefix(
        self, console: WintermuteConsole
    ) -> None:
        """Test resolving with explicit device prefix."""
        result = console._resolve_path("device.gateway.peripherals.uart0")
        assert result is not None
        assert result.name == "uart0"

    def test_resolve_path_quoted_name(self, console: WintermuteConsole) -> None:
        """Test resolving with quoted name containing spaces."""
        # Add a device with space in name
        console.operation.addDevice("my device", ipaddr="192.168.1.3")
        result = console._resolve_path('"my device"')
        assert result is not None
        assert result.hostname == "my device"

    def test_resolve_path_nonexistent(self, console: WintermuteConsole) -> None:
        """Test resolving a non-existent path."""
        result = console._resolve_path("nonexistent")
        assert result is None

    def test_resolve_path_invalid_peripheral(self, console: WintermuteConsole) -> None:
        """Test resolving an invalid peripheral path."""
        result = console._resolve_path("gateway.peripherals.nonexistent")
        assert result is None

    def test_resolve_path_empty_string(self) -> None:
        """Test resolving an empty string."""
        console = WintermuteConsole()
        result = console._resolve_path("")
        assert result is None

    def test_resolve_path_none_input(self) -> None:
        """Test resolving None input."""
        console = WintermuteConsole()
        # Type ignore for None input - testing edge case
        result = console._resolve_path("")  # Empty string instead of None
        assert result is None


class TestRemoveObjectFromParent:
    """Tests for the _remove_object_from_parent method."""

    @pytest.fixture
    def console(self) -> WintermuteConsole:
        """Create a WintermuteConsole instance with test data."""
        console = WintermuteConsole()
        # Add device with nested objects
        console.operation.addDevice(
            hostname="gateway",
            ipaddr="192.168.1.1",
            peripherals=[
                UART(name="uart0"),
                TPM(name="tpm0"),
            ],
            services=[
                Service(portNumber=22, app="ssh"),
            ],
            vulnerabilities=[
                Vulnerability(
                    title="CVE-2024-1234", cvss=9, description="Critical vulnerability"
                ),
            ],
        )
        return console

    def test_remove_root_device(self, console: WintermuteConsole) -> None:
        """Test removing a root-level device."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        success = console._remove_object_from_parent("gateway", device)
        assert success is True
        assert len(console.operation.devices) == 0

    def test_remove_root_user(self, console: WintermuteConsole) -> None:
        """Test removing a root-level user."""
        console.operation.addUser("admin", "Admin", "admin@test.com", teams=[])
        user = console.operation.users[0]
        success = console._remove_object_from_parent("admin", user)
        assert success is True
        assert len(console.operation.users) == 0

    def test_remove_root_aws_account(self, console: WintermuteConsole) -> None:
        """Test removing a root-level AWS account."""
        console.operation.addAWSAccount("test", account_id="123456789012")
        account = console.operation.cloud_accounts[0]
        success = console._remove_object_from_parent("test", account)
        assert success is True
        assert len(console.operation.cloud_accounts) == 0

    def test_remove_peripheral(self, console: WintermuteConsole) -> None:
        """Test removing a peripheral from device."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        peripheral = device.peripherals[0]
        success = console._remove_object_from_parent(
            "gateway.peripherals.uart0", peripheral
        )
        assert success is True
        assert len(device.peripherals) == 1
        assert device.peripherals[0].name == "tpm0"

    def test_remove_service(self, console: WintermuteConsole) -> None:
        """Test removing a service from device."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        service = device.services[0]
        success = console._remove_object_from_parent("gateway.services.ssh", service)
        assert success is True
        assert len(device.services) == 0

    def test_remove_vulnerability(self, console: WintermuteConsole) -> None:
        """Test removing a vulnerability from device."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        vuln = device.vulnerabilities[0]
        success = console._remove_object_from_parent(
            "gateway.vulnerabilities.CVE-2024-1234", vuln
        )
        assert success is True
        assert len(device.vulnerabilities) == 0

    def test_remove_nonexistent_object(self, console: WintermuteConsole) -> None:
        """Test removing a non-existent object."""
        _device = console.operation.getDeviceByHostname("gateway")
        fake_obj = MagicMock()
        fake_obj.__class__.__name__ = "fake"
        success = console._remove_object_from_parent(
            "gateway.fake.nonexistent", fake_obj
        )
        assert success is False

    def test_remove_from_nonexistent_parent(self, console: WintermuteConsole) -> None:
        """Test removing from a non-existent parent."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        success = console._remove_object_from_parent(
            "nonexistent.peripherals.uart0", device
        )
        assert success is False


class TestBuilderContext:
    """Tests for the BuilderContext class."""

    def test_builder_context_initialization(self) -> None:
        """Test BuilderContext initialization."""
        from wintermute.WintermuteConsole import BuilderContext

        ctx = BuilderContext("device", entity_class=Device)
        assert ctx.entity_name == "device"
        assert ctx.entity_class == Device
        assert ctx.properties == {}
        assert ctx._original_object is None

    def test_builder_context_with_properties(self) -> None:
        """Test BuilderContext with initial properties."""
        from wintermute.WintermuteConsole import BuilderContext

        ctx = BuilderContext(
            "device", entity_class=Device, parent_list_name="peripherals"
        )
        ctx.properties = {"hostname": "test", "ipaddr": "192.168.1.1"}
        assert ctx.properties["hostname"] == "test"
        assert ctx.properties["ipaddr"] == "192.168.1.1"
        assert ctx.parent_list_name == "peripherals"


class TestEditCommand:
    """Tests for the cmd_edit method."""

    @pytest.fixture
    def console(self) -> WintermuteConsole:
        """Create a WintermuteConsole instance with test data."""
        console = WintermuteConsole()
        # Add device with nested objects
        console.operation.addDevice(
            hostname="gateway",
            ipaddr="192.168.1.1",
            peripherals=[
                UART(name="uart0"),
            ],
        )
        return console

    def test_edit_device_enters_builder(self, console: WintermuteConsole) -> None:
        """Test that editing a device enters builder mode."""
        console.cmd_edit("gateway")
        assert len(console.builder_stack) == 1
        assert console.builder_stack[0].entity_name == "device"
        assert console.builder_stack[0]._original_object is not None

    def test_edit_peripheral_enters_builder(self, console: WintermuteConsole) -> None:
        """Test that editing a peripheral enters builder mode."""
        console.cmd_edit("gateway.peripherals.uart0")
        assert len(console.builder_stack) == 1
        assert console.builder_stack[0].entity_name == "uart"

    def test_edit_nonexistent_object(
        self, console: WintermuteConsole, capsys: CaptureFixture[str]
    ) -> None:
        """Test editing a non-existent object."""
        console.cmd_edit("nonexistent")
        captured = capsys.readouterr()
        assert "Root object 'nonexistent' not found" in captured.out


class TestDeleteCommand:
    """Tests for the cmd_delete method."""

    @pytest.fixture
    def console(self) -> WintermuteConsole:
        """Create a WintermuteConsole instance with test data."""
        console = WintermuteConsole()
        # Add device with nested objects
        console.operation.addDevice(
            hostname="gateway",
            ipaddr="192.168.1.1",
            peripherals=[
                UART(name="uart0"),
            ],
        )
        return console

    def test_delete_device(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test deleting a device."""
        monkeypatch.setattr("builtins.input", lambda _: "y")
        console.cmd_delete("gateway")
        assert len(console.operation.devices) == 0

    def test_delete_peripheral(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test deleting a peripheral."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        assert len(device.peripherals) == 1
        monkeypatch.setattr("builtins.input", lambda _: "y")
        console.cmd_delete("gateway.peripherals.uart0")
        assert len(device.peripherals) == 0

    def test_delete_cancelled(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test that delete is cancelled when user declines."""
        _device = console.operation.getDeviceByHostname("gateway")
        monkeypatch.setattr("builtins.input", lambda _: "n")
        console.cmd_delete("gateway")
        assert len(console.operation.devices) == 1

    def test_delete_nonexistent_object(
        self, console: WintermuteConsole, capsys: CaptureFixture[str]
    ) -> None:
        """Test deleting a non-existent object."""
        console.cmd_delete("nonexistent")
        captured = capsys.readouterr()
        assert "Root object 'nonexistent' not found" in captured.out

    def test_builder_save_edit_mode(self, console: WintermuteConsole) -> None:
        """Test that saving in builder mode updates the original object."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        console.cmd_edit("gateway")

        active_builder = console.builder_stack[-1]
        active_builder.properties["operatingsystem"] = "FreeRTOS"

        console.cmd_builder_save()

        assert device.operatingsystem == "FreeRTOS"
        assert len(console.operation.devices) == 1  # only gateway in this fixture

    def test_builder_save_new_user(self, console: WintermuteConsole) -> None:
        """Test creating a new user via builder."""
        console.cmd_add_enter("user")
        active_builder = console.builder_stack[-1]
        active_builder.properties.update(
            {
                "uid": "new_user",
                "name": "New User",
                "email": "new@test.com",
                "teams": ["red"],
            }
        )
        console.cmd_builder_save()
        assert any(u.uid == "new_user" for u in console.operation.users)

    def test_builder_save_nested_peripheral(self, console: WintermuteConsole) -> None:
        """Test attaching a new peripheral to a device via nested builder."""
        console.cmd_edit("gateway")
        console.cmd_add_enter("uart", parent_list="peripherals")

        inner_builder = console.builder_stack[-1]
        inner_builder.properties["name"] = "uart1"

        console.cmd_builder_save()  # Attached to parent builder
        assert len(console.builder_stack) == 1
        assert any(
            p.name == "uart1"
            for p in console.builder_stack[0].properties["peripherals"]
        )

        console.cmd_builder_save()  # Commit device update
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        assert any(p.name == "uart1" for p in device.peripherals)


class TestDeepTraversal:
    """Tests for deep traversal and complex pathing."""

    @pytest.fixture
    def console(self) -> WintermuteConsole:
        """Create a WintermuteConsole instance with rich test data."""
        console = WintermuteConsole()
        console.operation.addDevice(
            hostname="gateway",
            peripherals=[UART(name="uart0")],
            vulnerabilities=[Vulnerability(title="HOST_VULN", cvss=7)],
        )
        console.operation.addAWSAccount("prod", account_id="12345")
        console.operation.addUser("admin", "Admin", "admin@test.com", teams=[])
        return console

    def test_resolve_path_deep_vulnerability(self, console: WintermuteConsole) -> None:
        """Test resolving a vulnerability nested under a peripheral."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        uart = device.peripherals[0]
        vuln = Vulnerability(title="UART_VULN", cvss=5)
        uart.vulnerabilities.append(vuln)

        # gateway -> uart0 -> UART_VULN
        result = console._resolve_path("gateway.uart0.UART_VULN")
        assert result is not None
        assert result.title == "UART_VULN"

    def test_resolve_path_quoted_with_dots(self, console: WintermuteConsole) -> None:
        """Test resolving a path with dots inside quotes."""
        console.operation.addDevice("192.168.1.1", ipaddr="192.168.1.1")
        result = console._resolve_path('"192.168.1.1"')
        assert result is not None
        assert result.hostname == "192.168.1.1"

    def test_delete_deep_vulnerability(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test deleting a vulnerability nested under a peripheral."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        uart = device.peripherals[0]
        vuln = Vulnerability(title="UART_VULN", cvss=5)
        uart.vulnerabilities.append(vuln)

        assert vuln in uart.vulnerabilities
        monkeypatch.setattr("builtins.input", lambda _: "y")
        console.cmd_delete("gateway.uart0.UART_VULN")
        assert vuln not in uart.vulnerabilities

    def test_resolve_path_iam_user(self, console: WintermuteConsole) -> None:
        """Test resolving an IAM user path."""
        from wintermute.cloud.aws import IAMUser

        acc = console.operation.cloud_accounts[0]  # prod
        user = IAMUser(username="bob")
        acc.iamusers.append(user)

        result = console._resolve_path("prod.bob")
        assert result is not None
        assert result.username == "bob"

    def test_delete_iam_user(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test deleting an IAM user."""
        from wintermute.cloud.aws import IAMUser

        acc = console.operation.cloud_accounts[0]  # prod
        user = IAMUser(username="bob")
        acc.iamusers.append(user)

        monkeypatch.setattr("builtins.input", lambda _: "y")
        console.cmd_delete("prod.bob")
        assert user not in acc.iamusers

    def test_get_visible_state_deep_vars(self, console: WintermuteConsole) -> None:
        """Test get_visible_state on various object types to ensure vars(obj) is used."""
        device = console.operation.getDeviceByHostname("gateway")
        assert device is not None
        uart = device.peripherals[0]
        assert isinstance(uart, UART)
        uart.baudrate = 115200

        state = get_visible_state(uart)
        assert state["baudrate"] == 115200
        assert "pins" in state

    def test_remove_root_cloud_account(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test removing a root cloud account."""
        acc = console.operation.cloud_accounts[0]
        monkeypatch.setattr("builtins.input", lambda _: "y")
        console.cmd_delete("prod")
        assert acc not in console.operation.cloud_accounts

    def test_builder_save_aws_account(self, console: WintermuteConsole) -> None:
        """Test saving a new AWS account via builder."""
        console.cmd_add_enter("awsaccount")
        active_builder = console.builder_stack[-1]
        active_builder.properties.update({"name": "new_aws", "account_id": "99999"})
        console.cmd_builder_save()
        assert any(
            getattr(acc, "account_id", "") == "99999"
            for acc in console.operation.cloud_accounts
        )

    def test_resolve_path_explicit_types(self, console: WintermuteConsole) -> None:
        """Test path resolution with explicit typing prefixes."""
        assert console._resolve_path("device.gateway") is not None
        assert console._resolve_path("cloud_account.prod") is not None

    def test_resolve_path_nested_iam_role(self, console: WintermuteConsole) -> None:
        """Test resolving an IAM role."""
        from wintermute.cloud.aws import IAMRole

        acc = console.operation.cloud_accounts[0]
        role = IAMRole(role_name="admin_role")
        acc.iamroles.append(role)

        assert console._resolve_path("prod.admin_role") == role

    def test_resolve_path_service_by_port(self, console: WintermuteConsole) -> None:
        """Test resolving a service by its port number."""
        console.operation.devices[0].addService(portNumber=22, app="ssh")
        assert console._resolve_path("gateway.22") is not None

    def test_cmd_operation_create(self, console: WintermuteConsole) -> None:
        """Test operation create command."""
        console.cmd_operation_create("new_op")
        assert console.operation.operation_name == "new_op"
        assert "operation" in console.context_stack

    def test_cmd_operation_set(self, console: WintermuteConsole) -> None:
        """Test operation set command."""
        console.cmd_operation_enter()
        console.cmd_operation_set("ticket", "JIRA-123")
        assert console.operation.ticket == "JIRA-123"

    def test_cmd_status_smoke(self, console: WintermuteConsole) -> None:
        """Smoke test for cmd_status."""
        console.cmd_status()  # Should not raise error

    def test_cmd_vars_smoke(self, console: WintermuteConsole) -> None:
        """Smoke test for cmd_vars."""
        console.cmd_vars("gateway")  # Should not raise error

    def test_cmd_add_analyst(self, console: WintermuteConsole) -> None:
        """Test adding an analyst."""
        console.cmd_add_analyst("Alice", "aalice", "alice@test.com")
        assert any(a.userid == "aalice" for a in console.operation.analysts)

    def test_cmd_add_device(self, console: WintermuteConsole) -> None:
        """Test adding a device."""
        console.cmd_add_device("new_host", "10.0.0.1")
        assert any(d.hostname == "new_host" for d in console.operation.devices)

    def test_cmd_add_user(self, console: WintermuteConsole) -> None:
        """Test adding a user."""
        console.cmd_add_user("jsmith", "John Smith", "john@test.com")
        assert any(u.uid == "jsmith" for u in console.operation.users)

    def test_cmd_add_service(self, console: WintermuteConsole) -> None:
        """Test adding a service."""
        console.cmd_add_service("gateway", "80", "http")
        dev = console.operation.getDeviceByHostname("gateway")
        assert dev is not None
        assert any(s.portNumber == 80 for s in dev.services)

    def test_cmd_add_awsaccount(self, console: WintermuteConsole) -> None:
        """Test adding an AWS account."""
        console.cmd_add_awsaccount("dev_acc", "11111")
        assert any(acc.name == "dev_acc" for acc in console.operation.awsaccounts)

    def test_cmd_builder_set_and_show(self, console: WintermuteConsole) -> None:
        """Test builder set and show commands."""
        console.cmd_add_enter("device")
        console.cmd_builder_set("hostname", "builder-test")
        console.cmd_builder_set("portNumber", "80")  # test int conversion
        console.cmd_builder_set("verified", "true")  # test bool conversion

        ctx = console.builder_stack[-1]
        assert ctx.properties["hostname"] == "builder-test"
        assert ctx.properties["portNumber"] == 80
        assert ctx.properties["verified"] is True

        console.cmd_builder_show()  # Smoke test

    def test_cmd_back(self, console: WintermuteConsole) -> None:
        """Test back command in various contexts."""
        # In builder
        console.cmd_add_enter("device")
        assert len(console.builder_stack) == 1
        console.cmd_back()
        assert len(console.builder_stack) == 0

        # In operation context
        console.cmd_operation_enter()
        assert console.context_stack[-1] == "operation"
        console.cmd_back()
        assert console.context_stack[-1] == "wintermute"

    def test_cmd_operation_save_load_delete(self, console: WintermuteConsole) -> None:
        """Test operation save/load/delete commands with mocked backend."""
        from unittest.mock import MagicMock

        mock_backend = MagicMock()
        # Set up mock responses to avoid errors
        mock_backend.save.return_value = True
        mock_backend.load.return_value = {"operation_name": "test_op"}
        mock_backend.delete.return_value = True

        from wintermute.core import Operation

        Operation.register_backend("mock", mock_backend, make_default=True)

        console.operation.operation_name = "test_op"
        console.cmd_operation_save()
        assert mock_backend.save.called

        console.cmd_operation_load("test_op")
        assert mock_backend.load.called

        console.cmd_operation_delete("test_op")
        assert mock_backend.delete.called

    def test_cmd_edit_and_save_aws(self, console: WintermuteConsole) -> None:
        """Test editing and saving an AWS account."""
        acc = console.operation.cloud_accounts[0]  # prod
        console.cmd_edit("prod")

        active_builder = console.builder_stack[-1]
        active_builder.properties["description"] = "Updated Description"

        console.cmd_builder_save()
        assert acc.description == "Updated Description"

    def test_cmd_edit_and_save_user(self, console: WintermuteConsole) -> None:
        """Test editing and saving a user."""
        user = console.operation.users[0]  # admin
        console.cmd_edit("admin")

        active_builder = console.builder_stack[-1]
        active_builder.properties["name"] = "Admin Updated"

        console.cmd_builder_save()
        assert user.name == "Admin Updated"

    def test_cmd_workspace_switch(self, console: WintermuteConsole) -> None:
        """Test workspace switch command."""
        from unittest.mock import MagicMock

        mock_backend = MagicMock()
        mock_backend.load.return_value = {"operation_name": "new_ws"}
        from wintermute.core import Operation

        Operation.register_backend("mock", mock_backend, make_default=True)
        console.cmd_workspace_switch("new_ws")
        assert console.operation.operation_name == "new_ws"

    def test_cmd_backend_commands(self, console: WintermuteConsole) -> None:
        """Smoke test for backend commands."""
        import asyncio

        asyncio.run(console.cmd_backend_enter())
        assert console.context_stack[-1] == "backend"
        asyncio.run(console.cmd_backend_list())
        asyncio.run(console.cmd_backend_available())

    def test_cmd_ai_smoke(self, console: WintermuteConsole) -> None:
        """Smoke test for AI command (failure case when not initialized)."""
        import asyncio

        asyncio.run(console.cmd_ai())
        asyncio.run(console.cmd_ai("model", "list"))

    def test_cmd_use_cartridge_nonexistent(self, console: WintermuteConsole) -> None:
        """Test using a nonexistent cartridge."""
        console.cmd_use("nonexistent_cartridge")
        assert console.current_cartridge_name is None

    def test_cmd_builder_set_types(self, console: WintermuteConsole) -> None:
        """Test type inference in builder set."""
        console.cmd_add_enter("device")
        console.cmd_builder_set("port", "123")
        assert console.builder_stack[-1].properties["port"] == 123
        console.cmd_builder_set("flag", "false")
        assert console.builder_stack[-1].properties["flag"] is False

    def test_builder_nested_add_vulnerability(self, console: WintermuteConsole) -> None:
        """Test 'add vulnerability' inside builder."""
        console.cmd_add_enter("device")
        # Simulate REPL: add vulnerability
        from wintermute.findings import Vulnerability

        console.builder_stack.append(
            BuilderContext(
                "vulnerability", Vulnerability, parent_list_name="vulnerabilities"
            )
        )
        inner = console.builder_stack[-1]
        inner.properties["title"] = "NESTED_VULN"
        console.cmd_builder_save()

        assert "vulnerabilities" in console.builder_stack[0].properties
        assert (
            console.builder_stack[0].properties["vulnerabilities"][0].title
            == "NESTED_VULN"
        )

    def test_builder_nested_add_peripheral(self, console: WintermuteConsole) -> None:
        """Test 'add peripheral' inside builder."""
        console.cmd_add_enter("device")
        from wintermute.peripherals import UART

        console.builder_stack.append(
            BuilderContext("uart", UART, parent_list_name="peripherals")
        )
        inner = console.builder_stack[-1]
        inner.properties["name"] = "p1"
        console.cmd_builder_save()

        assert "peripherals" in console.builder_stack[0].properties
        assert console.builder_stack[0].properties["peripherals"][0].name == "p1"

    def test_resolve_path_noise_words(self, console: WintermuteConsole) -> None:
        """Test that noise words like 'peripherals' are skipped in path."""
        console.operation.devices[0].addService(portNumber=22, app="ssh")
        assert console._resolve_path("gateway.peripherals.uart0") is not None
        assert console._resolve_path("gateway.services.ssh") is not None

    def test_remove_object_from_parent_deep(
        self, console: WintermuteConsole, monkeypatch: MonkeyPatch
    ) -> None:
        """Test complex nested removal."""
        from wintermute.cloud.aws import IAMUser

        acc = console.operation.cloud_accounts[0]
        user = IAMUser(username="bob")
        acc.iamusers.append(user)

        monkeypatch.setattr("builtins.input", lambda _: "y")
        # Using full path including noise word
        console.cmd_delete("prod.iamusers.bob")
        assert user not in acc.iamusers

    def test_get_visible_state_private_filtering(self) -> None:
        """Test that private attributes are filtered out."""

        class Dummy:
            def __init__(self) -> None:
                self.public = "visible"
                self._private = "hidden"

        state = get_visible_state(Dummy())
        assert "public" in state
        assert "_private" not in state
