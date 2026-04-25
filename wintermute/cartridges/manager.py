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

import importlib
import inspect
import logging
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, List, Optional

from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.tools_runtime import unregister_tools
from wintermute.ai.utils.tool_factory import register_tools

log = logging.getLogger(__name__)

# Files that live next to the cartridges but are NOT themselves cartridges.
_NON_CARTRIDGE_MODULES = frozenset({"__init__", "__main__", "manager"})

# Suffix conventions accepted for the "primary class" inside a cartridge module.
_CARTRIDGE_CLASS_SUFFIX = "cartridge"


class CartridgeManager:
    """Singleton that owns the dynamic load/unload lifecycle of cartridges.

    Cartridges live in :mod:`wintermute.cartridges`. Each cartridge module
    exposes one primary class — either named after the module itself
    (``tpm20`` → ``tpm20``) or carrying the ``Cartridge`` suffix
    (``firmware_analysis`` → ``FirmwareAnalysisCartridge``). The manager
    discovers, instantiates, and registers each cartridge's public methods
    as AI tools so the LLM can call them by name.

    Singleton: a single instance is shared across the console, tests, and
    any other caller that constructs ``CartridgeManager()``. Use
    :meth:`reset_for_tests` to clear state between unit tests.
    """

    _instance: ClassVar[Optional["CartridgeManager"]] = None
    _initialized: bool

    def __new__(cls) -> "CartridgeManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        # Idempotent because ``__new__`` returns the same instance every time.
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.loaded_cartridges: Dict[str, Any] = {}
        # cartridge name -> tool names registered on its behalf
        self._tool_names: Dict[str, List[str]] = {}
        self.cartridges_path: Path = Path(__file__).resolve().parent
        # Observer pattern: callbacks fired whenever a successful load() or
        # unload() mutates the global tool registry. The MCP server uses
        # this hook to dynamically refresh its tool surface and emit a
        # `notifications/tools/list_changed` to connected clients.
        self._callbacks: List[Callable[[], None]] = []

    # ------------------------------------------------------------------
    # Test helper — explicit reset; do not use from production code.
    # ------------------------------------------------------------------

    @classmethod
    def reset_for_tests(cls) -> None:
        """Drop all loaded cartridges, unregister their tools, and clear
        any registered observer callbacks.

        Designed for test isolation. Safe to call when no instance exists.
        """
        if cls._instance is None:
            return
        instance = cls._instance
        for name in list(instance.loaded_cartridges.keys()):
            try:
                instance.unload(name)
            except Exception:
                log.exception("reset_for_tests: failed to unload %r", name)
        instance.loaded_cartridges.clear()
        instance._tool_names.clear()
        instance._callbacks.clear()

    # ------------------------------------------------------------------
    # Observer pattern — callbacks fire on every load/unload that mutates
    # the global tool registry. Observers are invoked synchronously in
    # registration order; exceptions in one callback do not prevent the
    # others from running.
    # ------------------------------------------------------------------

    def register_callback(self, fn: Callable[[], None]) -> None:
        """Subscribe ``fn`` to load/unload notifications.

        Callbacks are sync. If a subscriber needs to bridge into an
        asyncio event loop (e.g. the MCP server posting a
        ``notifications/tools/list_changed``) it is responsible for
        capturing its own loop and dispatching via
        :func:`asyncio.run_coroutine_threadsafe` or equivalent.
        """
        if fn not in self._callbacks:
            self._callbacks.append(fn)

    def unregister_callback(self, fn: Callable[[], None]) -> bool:
        """Drop ``fn`` from the observer list. Returns ``True`` if removed."""
        try:
            self._callbacks.remove(fn)
        except ValueError:
            return False
        return True

    def _fire_callbacks(self) -> None:
        for cb in list(self._callbacks):
            try:
                cb()
            except Exception:
                log.exception(
                    "CartridgeManager observer callback %r raised — continuing",
                    cb,
                )

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def list_available(self) -> List[str]:
        """Scan ``wintermute/cartridges/`` for cartridge module names.

        Excludes the package's plumbing files (``__init__.py``,
        ``manager.py``, ``__main__.py``) so the result only contains
        loadable cartridge module stems.
        """
        if not self.cartridges_path.is_dir():
            return []
        names: List[str] = []
        for entry in sorted(self.cartridges_path.iterdir()):
            if entry.suffix != ".py":
                continue
            stem = entry.stem
            if stem in _NON_CARTRIDGE_MODULES:
                continue
            names.append(stem)
        return names

    def list_loaded(self) -> List[str]:
        """Return names of currently loaded cartridges (load order)."""
        return list(self.loaded_cartridges.keys())

    # ------------------------------------------------------------------
    # Load / unload
    # ------------------------------------------------------------------

    def load(self, name: str) -> bool:
        """Import the cartridge module, instantiate its primary class, and
        register every public method as an AI tool.

        Args:
            name: Cartridge module stem, e.g. ``"tpm20"`` or
                ``"firmware_analysis"``. Must be present in
                :meth:`list_available`.

        Returns:
            ``True`` if the cartridge transitioned from "not loaded" to
            "loaded" and at least one method was registered. Returns
            ``True`` even when zero methods were registered, as long as
            the instance itself was successfully created.

        Raises:
            ModuleNotFoundError: If the module cannot be imported.
            RuntimeError: If no primary class can be located, or if the
                instance constructor raises (e.g., ``JTAGCartridge`` when
                ``openocd`` is missing). The original exception is wrapped.
        """
        if name in self.loaded_cartridges:
            log.info("Cartridge %r is already loaded.", name)
            return False

        module = importlib.import_module(f"wintermute.cartridges.{name}")
        cls = self._find_primary_class(module, name)
        if cls is None:
            raise RuntimeError(
                f"Cartridge {name!r}: no primary class found "
                f"(expected a class matching the module name or ending in "
                f"{_CARTRIDGE_CLASS_SUFFIX!r})."
            )
        try:
            instance = cls()
        except Exception as exc:
            raise RuntimeError(
                f"Cartridge {name!r}: failed to instantiate {cls.__name__}: {exc}"
            ) from exc

        registered_names = self._register_instance_methods(name, instance)
        self.loaded_cartridges[name] = instance
        self._tool_names[name] = registered_names
        log.info(
            "Loaded cartridge %r (%s) — %d tool(s) registered.",
            name,
            cls.__name__,
            len(registered_names),
        )
        # Observer broadcast: fire AFTER the manager state is fully
        # consistent so callbacks observe the post-load registry.
        self._fire_callbacks()
        return True

    def unload(self, name: str) -> bool:
        """Remove the cartridge instance and unregister every tool that
        was registered on its behalf.

        Returns ``True`` if the cartridge was loaded prior to the call.
        """
        if name not in self.loaded_cartridges:
            return False
        tool_names = self._tool_names.pop(name, [])
        unregister_tools(tool_names)
        del self.loaded_cartridges[name]
        log.info(
            "Unloaded cartridge %r — %d tool(s) unregistered.",
            name,
            len(tool_names),
        )
        # Observer broadcast: fire AFTER the manager state is fully
        # consistent so callbacks observe the post-unload registry.
        self._fire_callbacks()
        return True

    def get(self, name: str) -> Any:
        """Return the live cartridge instance, or raise ``KeyError``."""
        if name not in self.loaded_cartridges:
            raise KeyError(f"Cartridge {name!r} is not loaded.")
        return self.loaded_cartridges[name]

    def tool_names_for(self, name: str) -> List[str]:
        """Return the AI tool names that belong to the given cartridge."""
        return list(self._tool_names.get(name, []))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_primary_class(module: Any, module_stem: str) -> Optional[type]:
        """Locate the primary class of a cartridge module.

        Resolution order:
            1. Class whose name equals the module stem (case-insensitive).
            2. First class whose name ends in ``Cartridge`` (case-insens.).
            3. First class actually defined in the module (i.e. not imported).

        ``None`` is returned if nothing matches — the caller decides how
        to surface the failure.
        """
        candidates: List[type] = []
        target_lower = module_stem.lower()
        suffix_match: Optional[type] = None
        own_module: Optional[type] = None

        for member_name, member in inspect.getmembers(module, inspect.isclass):
            if getattr(member, "__module__", "") != module.__name__:
                # Imported into the module, not defined in it.
                continue
            candidates.append(member)
            lower_name = member_name.lower()
            if lower_name == target_lower:
                return member
            if suffix_match is None and lower_name.endswith(_CARTRIDGE_CLASS_SUFFIX):
                suffix_match = member
            if own_module is None:
                own_module = member

        if suffix_match is not None:
            return suffix_match
        return own_module

    def _register_instance_methods(
        self, cartridge_name: str, instance: Any
    ) -> List[str]:
        """Walk the instance's public methods and feed them to the
        :func:`register_tools` adapter.

        Methods that fail conversion (unusual signatures, unsupported
        annotations) are skipped with a warning so a single bad method
        cannot block the rest of the cartridge from loading.
        """
        callables: List[Callable[..., Any]] = []
        for attr_name in dir(instance):
            if attr_name.startswith("_"):
                continue
            try:
                member = getattr(instance, attr_name)
            except Exception:
                continue
            if not inspect.ismethod(member):
                continue
            callables.append(member)

        registered: List[str] = []
        for fn in callables:
            try:
                [tool] = register_tools([fn])
            except Exception as exc:
                log.warning(
                    "Cartridge %r: skipping %s — %s",
                    cartridge_name,
                    fn.__name__,
                    exc,
                )
                continue
            try:
                global_tool_registry.register(tool)
            except Exception as exc:
                log.warning(
                    "Cartridge %r: failed to register %s: %s",
                    cartridge_name,
                    tool.name,
                    exc,
                )
                continue
            registered.append(tool.name)
        return registered


__all__ = ["CartridgeManager"]
