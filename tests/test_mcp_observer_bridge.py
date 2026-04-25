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
from typing import Any, Iterator

import pytest

from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.tools_runtime import unregister_tools
from wintermute.cartridges.manager import CartridgeManager


@pytest.fixture(autouse=True)
def isolate_manager() -> Iterator[None]:
    """Hard-reset cartridge state between tests, **preserving** any
    callbacks registered at module-import time (notably the WintermuteMCP
    bridge). Without this preservation we'd lose the wiring we explicitly
    want to verify."""
    snapshot = list(global_tool_registry._tools.keys())
    callback_snapshot = list(CartridgeManager()._callbacks)
    CartridgeManager.reset_for_tests()
    # Re-register the original observers so import-time wiring survives.
    for cb in callback_snapshot:
        CartridgeManager().register_callback(cb)
    try:
        yield
    finally:
        CartridgeManager.reset_for_tests()
        for cb in callback_snapshot:
            CartridgeManager().register_callback(cb)
        added = set(global_tool_registry._tools.keys()) - set(snapshot)
        unregister_tools(added)


# ---------------------------------------------------------------------------
# Observer pattern in CartridgeManager
# ---------------------------------------------------------------------------


def test_register_callback_appends() -> None:
    mgr = CartridgeManager()

    def cb() -> None:
        pass

    mgr.register_callback(cb)
    assert cb in mgr._callbacks


def test_register_callback_is_idempotent() -> None:
    """Re-registering the same callable does not add a duplicate."""
    mgr = CartridgeManager()
    calls: list[int] = []

    def cb() -> None:
        calls.append(1)

    mgr.register_callback(cb)
    mgr.register_callback(cb)
    assert mgr._callbacks.count(cb) == 1


def test_unregister_callback() -> None:
    mgr = CartridgeManager()

    def cb() -> None:
        pass

    mgr.register_callback(cb)
    assert mgr.unregister_callback(cb) is True
    assert mgr.unregister_callback(cb) is False
    assert cb not in mgr._callbacks


def test_callback_fires_on_load() -> None:
    mgr = CartridgeManager()
    calls: list[str] = []

    def cb() -> None:
        # Must observe the post-load registry: the cartridge is already
        # in loaded_cartridges by the time the callback runs.
        calls.append(",".join(mgr.list_loaded()))

    mgr.register_callback(cb)
    mgr.load("firmware_analysis")
    assert calls == ["firmware_analysis"]


def test_callback_fires_on_unload() -> None:
    mgr = CartridgeManager()
    mgr.load("firmware_analysis")

    calls: list[str] = []

    def cb() -> None:
        calls.append(",".join(mgr.list_loaded()))

    mgr.register_callback(cb)
    mgr.unload("firmware_analysis")
    # Post-unload registry observed: empty.
    assert calls == [""]


def test_callback_does_not_fire_on_failed_load() -> None:
    """A second `load` of an already-loaded cartridge is a no-op (returns
    False) — observers must NOT be notified."""
    mgr = CartridgeManager()
    mgr.load("firmware_analysis")
    calls: list[None] = []

    def cb() -> None:
        calls.append(None)

    mgr.register_callback(cb)
    assert mgr.load("firmware_analysis") is False
    assert calls == []


def test_callback_does_not_fire_on_failed_unload() -> None:
    mgr = CartridgeManager()
    calls: list[None] = []

    def cb() -> None:
        calls.append(None)

    mgr.register_callback(cb)
    assert mgr.unload("not_loaded") is False
    assert calls == []


def test_failing_callback_doesnt_break_chain() -> None:
    """One subscriber raising must not prevent later subscribers running."""
    mgr = CartridgeManager()

    def cb_bad() -> None:
        raise RuntimeError("oops")

    calls: list[None] = []

    def cb_good() -> None:
        calls.append(None)

    mgr.register_callback(cb_bad)
    mgr.register_callback(cb_good)
    mgr.load("firmware_analysis")
    assert calls == [None]


def test_callbacks_receive_consistent_state() -> None:
    """Callback observes loaded_cartridges, _tool_names, and the global
    registry all in lock-step."""
    mgr = CartridgeManager()
    snapshot: dict[str, list[str]] = {}

    def cb() -> None:
        if "firmware_analysis" in mgr.list_loaded():
            snapshot["tools"] = list(mgr.tool_names_for("firmware_analysis"))
            # Each tool name should already be in the global registry.
            snapshot["in_registry"] = [
                name
                for name in snapshot["tools"]
                if name in global_tool_registry._tools
            ]

    mgr.register_callback(cb)
    mgr.load("firmware_analysis")
    assert snapshot["tools"]
    assert snapshot["in_registry"] == snapshot["tools"]


# ---------------------------------------------------------------------------
# WintermuteMCP dynamic bridge
# ---------------------------------------------------------------------------


@pytest.fixture()
def mcp_mod(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Import the MCP module and reset its bridge bookkeeping.

    The module is import-cached, so we cannot truly re-import cheaply;
    instead we reset the bridge's bookkeeping (``_CARTRIDGE_BOUND_TOOL_NAMES``,
    ``_MCP_EVENT_LOOP``) and re-invoke ``_register_cartridge_observer`` so
    the import-time wiring survives the autouse manager reset regardless
    of test collection order.
    """
    import wintermute.WintermuteMCP as module

    original_bound = set(module._CARTRIDGE_BOUND_TOOL_NAMES)
    original_loop = module._MCP_EVENT_LOOP

    for name in list(module._CARTRIDGE_BOUND_TOOL_NAMES):
        try:
            module.mcp.remove_tool(name)
        except Exception:
            pass
    module._CARTRIDGE_BOUND_TOOL_NAMES.clear()
    module._MCP_EVENT_LOOP = None
    # Idempotent re-registration so this test always observes the wiring,
    # even if a previous test's teardown wiped the callback list.
    module._register_cartridge_observer()
    try:
        yield module
    finally:
        for name in list(module._CARTRIDGE_BOUND_TOOL_NAMES):
            try:
                module.mcp.remove_tool(name)
            except Exception:
                pass
        module._CARTRIDGE_BOUND_TOOL_NAMES.clear()
        module._CARTRIDGE_BOUND_TOOL_NAMES.update(original_bound)
        module._MCP_EVENT_LOOP = original_loop


def test_mcp_module_does_not_statically_bind_cartridges(mcp_mod: Any) -> None:
    """The static `_build_hardware_methods` / `_HARDWARE_TOOLS_BOUND` flow
    is gone: importing the module must NOT auto-bind any cartridge tool."""
    assert not hasattr(mcp_mod, "_build_hardware_methods")
    assert not hasattr(mcp_mod, "_bind_hardware_cartridges")
    assert not hasattr(mcp_mod, "_HARDWARE_TOOLS_BOUND")


def test_observer_is_registered_at_module_import(mcp_mod: Any) -> None:
    """The bridge must register its callback with the singleton at import."""
    mgr = CartridgeManager()
    assert mcp_mod._on_cartridge_changed in mgr._callbacks


def test_load_dynamically_adds_tool_to_fastmcp(mcp_mod: Any) -> None:
    mgr = CartridgeManager()
    # Re-register because the autouse fixture cleared everything.
    mgr.register_callback(mcp_mod._on_cartridge_changed)

    mgr.load("firmware_analysis")
    expected = {
        "analyze_entropy",
        "scan_for_secrets",
        "extract_strings",
        "find_base_address",
    }
    assert expected <= mcp_mod._CARTRIDGE_BOUND_TOOL_NAMES


def test_unload_dynamically_removes_tool_from_fastmcp(
    mcp_mod: Any,
) -> None:
    mgr = CartridgeManager()
    mgr.register_callback(mcp_mod._on_cartridge_changed)

    mgr.load("firmware_analysis")
    assert "analyze_entropy" in mcp_mod._CARTRIDGE_BOUND_TOOL_NAMES

    mgr.unload("firmware_analysis")
    assert mcp_mod._CARTRIDGE_BOUND_TOOL_NAMES == set()


def test_sync_skips_decorator_registered_tools(mcp_mod: Any) -> None:
    """The bridge must never remove the static `@mcp.tool()`-registered
    handlers (operations / vulns / SSH sessions / etc.).

    We sample one well-known static tool name and confirm it is *not* in
    the cartridge-bound set after a sync."""
    mcp_mod._sync_fastmcp_tools_from_registry()
    # The MCP module ships static tools like `list_active_objects`,
    # `create_operation`, etc. None of them should be tracked as
    # cartridge-bound.
    assert "list_active_objects" not in mcp_mod._CARTRIDGE_BOUND_TOOL_NAMES
    assert "create_operation" not in mcp_mod._CARTRIDGE_BOUND_TOOL_NAMES


def test_broadcast_no_request_context_is_noop(mcp_mod: Any) -> None:
    """Outside an MCP request, broadcast must log + return without raising."""
    asyncio.run(mcp_mod._broadcast_tool_list_changed())  # must not raise


def test_broadcast_uses_active_session(
    mcp_mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a request_context with a session is available, broadcast
    forwards to ``session.send_tool_list_changed()``."""
    sent = asyncio.Event()

    class _FakeSession:
        async def send_tool_list_changed(self) -> None:
            sent.set()

    class _FakeCtx:
        session = _FakeSession()

    # Patch the underlying low-level server to expose our fake context.
    monkeypatch.setattr(
        type(mcp_mod.mcp._mcp_server),
        "request_context",
        property(lambda self: _FakeCtx()),
    )
    asyncio.run(mcp_mod._broadcast_tool_list_changed())
    assert sent.is_set()


def test_callback_skips_broadcast_when_loop_inactive(mcp_mod: Any) -> None:
    """If the MCP server isn't running yet, the sync part still happens
    but the broadcast is silently skipped (no exception)."""
    assert mcp_mod._MCP_EVENT_LOOP is None
    mgr = CartridgeManager()
    mgr.register_callback(mcp_mod._on_cartridge_changed)
    # Should NOT raise even though there's no event loop captured.
    mgr.load("firmware_analysis")
    assert "analyze_entropy" in mcp_mod._CARTRIDGE_BOUND_TOOL_NAMES


def test_callback_dispatches_broadcast_via_captured_loop(
    mcp_mod: Any,
) -> None:
    """When ``_MCP_EVENT_LOOP`` is populated (lifespan captured it), a
    cartridge change schedules ``_broadcast_tool_list_changed`` on that
    loop."""
    import threading

    broadcast_called = threading.Event()

    async def _fake_broadcast() -> None:
        broadcast_called.set()

    # Stand up a real background asyncio loop to imitate the running
    # MCP server.
    loop_ready = threading.Event()
    container: list[asyncio.AbstractEventLoop] = []

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        container.append(loop)
        loop_ready.set()
        loop.run_forever()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    loop_ready.wait()
    bg_loop = container[0]

    try:
        mcp_mod._MCP_EVENT_LOOP = bg_loop
        # Replace the broadcaster so the test doesn't need a real session.
        original = mcp_mod._broadcast_tool_list_changed
        mcp_mod._broadcast_tool_list_changed = _fake_broadcast
        try:
            mgr = CartridgeManager()
            mgr.register_callback(mcp_mod._on_cartridge_changed)
            mgr.load("firmware_analysis")
            # The coroutine was scheduled cross-thread; wait briefly.
            assert broadcast_called.wait(timeout=2.0)
        finally:
            mcp_mod._broadcast_tool_list_changed = original
            mcp_mod._MCP_EVENT_LOOP = None
    finally:
        bg_loop.call_soon_threadsafe(bg_loop.stop)
        thread.join(timeout=2.0)
