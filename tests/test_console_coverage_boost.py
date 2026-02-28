# -*- coding: utf-8 -*-
"""
Coverage boost tests for WintermuteConsole.
"""

from unittest.mock import MagicMock, patch

import pytest

from wintermute.core import Device, Operation
from wintermute.findings import Vulnerability
from wintermute.peripherals import UART
from wintermute.WintermuteConsole import (
    BuilderContext,
    WintermuteConsole,
)


@pytest.fixture
def console() -> WintermuteConsole:
    return WintermuteConsole()


def test_format_value(console: WintermuteConsole) -> None:
    from enum import Enum

    class TestEnum(Enum):
        VAL = 1

    assert console._format_value(TestEnum.VAL) == "VAL"
    assert console._format_value([1, 2]) == "[2 items]"
    assert console._format_value({"a": 1}) == "{1 keys}"
    assert console._format_value(None) == "[dim]None[/dim]"
    assert console._format_value(123) == "123"


def test_cmd_status_no_op(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    prev = Operation._active
    try:
        Operation._active = None
        console.cmd_status()
        captured = capsys.readouterr()
        assert "NO ACTIVE OPERATION" in captured.out
    finally:
        Operation._active = prev


def test_cmd_status_with_op(console: WintermuteConsole) -> None:
    op = Operation(operation_name="test-op")
    op.addDevice("host1")
    op.addUser("user1", "User One", "user1@test.com", teams=[])
    op.addAWSAccount("aws1", account_id="123")
    with patch("wintermute.core.Operation._active", op):
        console.cmd_status()


def test_cmd_operation_save_failure(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.operation.operation_name = "test"
    mock_backend = MagicMock()
    mock_backend.save.return_value = False
    with patch("wintermute.core.Operation._backend", mock_backend):
        console.cmd_operation_save()
        captured = capsys.readouterr()
        assert "Save failed" in captured.out


def test_cmd_operation_load_failure(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_backend = MagicMock()
    mock_backend.load.return_value = None
    with patch("wintermute.core.Operation._backend", mock_backend):
        console.cmd_operation_load("nonexistent")
        captured = capsys.readouterr()
        assert "Could not load" in captured.out


def test_cmd_operation_load_success(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_backend = MagicMock()
    mock_backend.load.return_value = {"operation_name": "loaded-op"}
    with patch("wintermute.core.Operation._backend", mock_backend):
        console.cmd_operation_load("loaded-op")
        captured = capsys.readouterr()
        assert "Loaded operation" in captured.out
        assert console.operation.operation_name == "loaded-op"


def test_cmd_operation_delete_success(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_backend = MagicMock()
    mock_backend.delete.return_value = True
    with patch("wintermute.core.Operation._backend", mock_backend):
        console.cmd_operation_delete("test")
        captured = capsys.readouterr()
        assert "Deleted operation" in captured.out


def test_cmd_operation_delete_failure(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_backend = MagicMock()
    mock_backend.delete.return_value = False
    with patch("wintermute.core.Operation._backend", mock_backend):
        console.cmd_operation_delete("test")
        captured = capsys.readouterr()
        assert "Failed to delete" in captured.out


def test_cmd_operation_delete_no_support(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    # Use a real class instance that doesn't have 'delete'
    class NoDelete:
        pass

    with patch("wintermute.core.Operation._backend", NoDelete()):
        console.cmd_operation_delete("test")
        captured = capsys.readouterr()
        assert "does not support deletion" in captured.out


def test_cmd_edit_failure(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.cmd_edit("nonexistent")
    captured = capsys.readouterr()
    assert "Could not find object" in captured.out


def test_cmd_set_no_cartridge(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.cmd_set("opt", "val")
    captured = capsys.readouterr()
    assert "No cartridge selected" in captured.out


def test_cmd_run_no_cartridge(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.cmd_run()
    captured = capsys.readouterr()
    assert "No cartridge selected" in captured.out


def test_show_options_no_cartridge(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.show_options()
    captured = capsys.readouterr()
    assert "No cartridge selected" in captured.out


def test_show_commands_topics(console: WintermuteConsole) -> None:
    console.show_commands("ai")
    console.show_commands("tools")
    console.show_commands("add")


@pytest.mark.asyncio
async def test_cmd_ai_model_list(console: WintermuteConsole) -> None:
    console.ai_router = MagicMock()
    mock_provider = MagicMock()
    mock_provider.list_models.return_value = []
    with patch("wintermute.ai.provider.llms.get", return_value=mock_provider):
        await console.cmd_ai("model", "list")


@pytest.mark.asyncio
async def test_cmd_ai_model_set(console: WintermuteConsole) -> None:
    console.ai_router = MagicMock()
    await console.cmd_ai("model", "set", "test-model")
    console.ai_router.set_default.assert_called_with(model="test-model")


@pytest.mark.asyncio
async def test_cmd_ai_rag_list(console: WintermuteConsole) -> None:
    console.ai_router = MagicMock()
    with patch("wintermute.ai.provider.llms.providers", return_value=["rag-test"]):
        mock_rag = MagicMock()
        mock_rag.persist_dir = "/tmp"
        with patch("wintermute.ai.provider.llms.get", return_value=mock_rag):
            await console.cmd_ai("rag", "list")


@pytest.mark.asyncio
async def test_cmd_ai_rag_use(console: WintermuteConsole) -> None:
    console.ai_router = MagicMock()
    with patch("wintermute.ai.provider.llms.providers", return_value=["rag-test"]):
        await console.cmd_ai("rag", "use", "rag-test")
        console.ai_router.set_default.assert_called_with(provider="rag-test")


@pytest.mark.asyncio
async def test_cmd_ai_rag_off(console: WintermuteConsole) -> None:
    console.ai_router = MagicMock()
    with patch("wintermute.ai.provider.llms.providers", return_value=["bedrock"]):
        await console.cmd_ai("rag", "off")
        console.ai_router.set_default.assert_called_with(provider="bedrock")


@pytest.mark.asyncio
async def test_cmd_ai_chat(console: WintermuteConsole) -> None:
    console.ai_router = MagicMock()
    mock_resp = MagicMock()
    mock_resp.content = "Hello"
    mock_resp.tool_calls = []
    with patch(
        "wintermute.WintermuteConsole.tool_calling_chat", return_value=mock_resp
    ):
        await console.cmd_ai("chat", "hi")


def test_scan_backends(console: WintermuteConsole) -> None:
    # Just a smoke test for now as it scans the filesystem
    console._scan_backends()


def test_update_completer_smoke(console: WintermuteConsole) -> None:
    console.update_completer()
    console.builder_stack.append(BuilderContext("device", entity_class=Device))
    console.update_completer()


def test_cmd_builder_save_new_service_root(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.cmd_add_enter("service")
    ctx = console.builder_stack[-1]
    ctx.properties.update({"portNumber": 80, "app": "http"})
    # Without device_hostname, should fail
    console.cmd_builder_save()
    captured = capsys.readouterr()
    assert "requires 'device_hostname'" in captured.out

    # With device_hostname
    console.operation.addDevice("host1")
    ctx.properties["device_hostname"] = "host1"
    console.cmd_builder_save()
    assert len(console.operation.devices[0].services) == 1


def test_cmd_builder_save_unsupported_root(
    console: WintermuteConsole, capsys: pytest.CaptureFixture[str]
) -> None:
    console.cmd_add_enter("uart")  # Not supported at root
    console.cmd_builder_save()
    captured = capsys.readouterr()
    assert "Cannot save uart at root level" in captured.out


def test_cmd_back_root(console: WintermuteConsole) -> None:
    console.cmd_back()  # Should not raise


def test_cmd_delete_success(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    console.operation.addDevice("host-to-delete")
    monkeypatch.setattr("builtins.input", lambda _: "y")
    console.cmd_delete("host-to-delete")
    assert console.operation.getDeviceByHostname("host-to-delete") is None


def test_cmd_delete_cancel(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    console.operation.addDevice("host-to-keep")
    monkeypatch.setattr("builtins.input", lambda _: "n")
    console.cmd_delete("host-to-keep")
    assert console.operation.getDeviceByHostname("host-to-keep") is not None


def test_cmd_delete_user(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    console.operation.addUser("user-to-delete", "Name", "email", teams=[])
    monkeypatch.setattr("builtins.input", lambda _: "y")
    console.cmd_delete("user-to-delete")
    assert not any(u.uid == "user-to-delete" for u in console.operation.users)


def test_cmd_delete_aws(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    console.operation.addAWSAccount("aws-to-delete", account_id="123")
    monkeypatch.setattr("builtins.input", lambda _: "y")
    console.cmd_delete("aws-to-delete")
    assert not any(a.name == "aws-to-delete" for a in console.operation.cloud_accounts)


def test_cmd_delete_peripheral(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    console.operation.addDevice("host1")
    dev = console.operation.getDeviceByHostname("host1")
    assert dev is not None
    dev.peripherals.append(UART(name="u1"))
    monkeypatch.setattr("builtins.input", lambda _: "y")
    console.cmd_delete("host1.peripherals.u1")
    assert len(dev.peripherals) == 0


def test_cmd_delete_vulnerability(
    console: WintermuteConsole, monkeypatch: pytest.MonkeyPatch
) -> None:
    console.operation.addDevice("host1")
    dev = console.operation.getDeviceByHostname("host1")
    assert dev is not None
    dev.vulnerabilities.append(Vulnerability(title="v1"))
    monkeypatch.setattr("builtins.input", lambda _: "y")
    console.cmd_delete("host1.vulnerabilities.v1")
    assert len(dev.vulnerabilities) == 0


def test_cmd_add_service_interactive(console: WintermuteConsole) -> None:
    console.operation.addDevice("host1")
    console.cmd_add_service("host1", "80", "http")
    dev = console.operation.getDeviceByHostname("host1")
    assert dev is not None
    assert any(s.portNumber == 80 for s in dev.services)
