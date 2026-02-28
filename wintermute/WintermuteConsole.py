# -*- coding: utf-8 -*-
"""
Wintermute REPL Console
-----------------------
A Metasploit-style REPL using prompt-toolkit and rich.
"""

import asyncio
import importlib
import inspect
import logging
import os
import re
import shlex
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.table import Table
from rich.tree import Tree

from wintermute.ai.bootstrap import bootstrap_rags, init_router
from wintermute.ai.provider import Router, llms
from wintermute.ai.tools_runtime import ToolsRuntime
from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.use import tool_calling_chat
from wintermute.ai.utils.tool_factory import register_tools
from wintermute.backends.json_storage import JsonFileBackend
from wintermute.basemodels import CloudAccount
from wintermute.cloud.aws import AWSService, AWSUser, IAMRole, IAMUser
from wintermute.core import Analyst, AWSAccount, Device, Operation, Service, User
from wintermute.findings import Vulnerability
from wintermute.hardware import Architecture, Memory, Processor
from wintermute.peripherals import (
    JTAG,
    TPM,
    UART,
    USB,
    Bluetooth,
    Ethernet,
    PCIe,
    Wifi,
)
from wintermute.reports import Report
from wintermute.tickets import Ticket


def get_visible_state(obj: Any) -> dict[str, Any]:
    """Return a dict of all visible state from an object.

    Filters out:
    - Any key found in obj.__schema__
    - Any key starting with _ (except pins which should be visible)

    Args:
        obj: The object to inspect.

    Returns:
        A dict of visible state items.
    """
    schema = getattr(obj, "__schema__", {})
    schema_keys = set(schema.keys())

    result: dict[str, Any] = {}
    # Use vars(obj) as requested to ensure all properties remain editable
    for key, value in vars(obj).items():
        # Skip schema keys and private attributes (except pins which should be visible)
        if key in schema_keys or (key.startswith("_") and key != "pins"):
            continue
        result[key] = value

    # If pins attribute exists, ensure it's returned for visibility
    if hasattr(obj, "pins") and isinstance(obj.pins, dict):
        # We keep it as a dict, the formatter in cmd_status/cmd_vars handles display
        result["pins"] = obj.pins

    return result


# Configure logging
logging.basicConfig(
    filename="wintermute_console.log",
    format="%(asctime)s %(levelname)-8s WintermuteConsole - %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class BuilderContext:
    def __init__(
        self,
        entity_name: str,
        entity_class: Optional[Type[Any]] = None,
        parent_list_name: Optional[str] = None,
    ) -> None:
        self.entity_name = entity_name
        self.entity_class = entity_class
        self.parent_list_name = parent_list_name
        self.properties: Dict[str, Any] = {}
        # Store original object reference for edit mode
        self._original_object: Any | None = None


class WintermuteConsole:
    def __init__(self) -> None:
        self.rich_console = Console()
        self.session: PromptSession[Any] = PromptSession(history=InMemoryHistory())
        self.operation = Operation(operation_name="default")
        self.tools_runtime = ToolsRuntime()

        # Local context (Cartridge)
        self.context_stack: List[str] = ["wintermute"]
        self.current_cartridge_name: Optional[str] = None
        self.current_cartridge_instance: Optional[Any] = None
        self.cartridge_options: Dict[str, Any] = {}

        # Builder Context
        self.builder_stack: List[BuilderContext] = []

        # Entity Factory Mapping
        self.ENTITY_CLASSES: dict[str, type[Any]] = {
            "analyst": Analyst,
            "device": Device,
            "user": User,
            "cloudaccount": CloudAccount,
            "awsaccount": AWSAccount,  # backward compat alias
            "awsuser": AWSUser,
            "iamuser": IAMUser,
            "iamrole": IAMRole,
            "awsservice": AWSService,
            "service": Service,
            "uart": UART,
            "jtag": JTAG,
            "tpm": TPM,
            "ethernet": Ethernet,
            "wifi": Wifi,
            "bluetooth": Bluetooth,
            "usb": USB,
            "pcie": PCIe,
            "processor": Processor,
            "architecture": Architecture,
            "memory": Memory,
            "vulnerability": Vulnerability,
        }

        self.PERIPHERAL_MAP: dict[str, type[Any]] = {
            "uart": UART,
            "jtag": JTAG,
            "tpm": TPM,
            "ethernet": Ethernet,
            "wifi": Wifi,
            "bluetooth": Bluetooth,
            "usb": USB,
            "pcie": PCIe,
        }

        self.CLOUD_NESTED_MAP: dict[str, tuple[type[Any], str]] = {
            "awsuser": (AWSUser, "users"),
            "iamuser": (IAMUser, "iamusers"),
            "iamrole": (IAMRole, "iamroles"),
            "awsservice": (AWSService, "services"),
        }

        # Cloud type → entity class mapping
        self.CLOUD_TYPE_MAP: dict[str, type[Any]] = {
            "aws": AWSAccount,
            "generic": CloudAccount,
        }

        # Modules Cache
        self.cartridges_path = os.path.join(os.path.dirname(__file__), "cartridges")
        self.available_cartridges: List[str] = self._scan_cartridges()

        # AI Integration
        self.ai_router: Optional[Router] = None
        try:
            self.ai_router = init_router()
        except Exception:
            # Fallback if AWS/Bedrock credentials not set during init
            pass

        # Auto-register default backend if none exists
        if Operation._backend is None:
            default_path = ".wintermute_data"
            try:
                backend = JsonFileBackend(base_path=default_path)
                Operation.register_backend("json_storage", backend, make_default=True)
                # We don't print here to keep startup clean, but it prevents the "No Backend" error.
            except Exception as e:
                logger.warning(f"Failed to initialize default backend: {e}")

        self.style = Style.from_dict(
            {
                "prompt": "bold ansibrightcyan",
                "path": "bold ansibrightgreen",
                "context": "bold ansibrightmagenta",
                "separator": "ansicyan",
            }
        )

    def _scan_cartridges(self) -> List[str]:
        """Scans wintermute/cartridges for available modules."""
        cartridges: List[str] = []
        if not os.path.exists(self.cartridges_path):
            return cartridges
        for item in os.listdir(self.cartridges_path):
            if item.endswith(".py") and item != "__init__.py":
                cartridges.append(item[:-3])
        return cartridges

    def _find_primary_class(self, module: Any, name: str) -> Optional[Type[Any]]:
        """Finds the cartridge class within a module."""
        for member_name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and obj.__module__ == module.__name__:
                if member_name.lower() == name.lower():
                    return obj
        # Fallback to first class found if name match fails
        for member_name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and obj.__module__ == module.__name__:
                return obj
        return None

    def _is_cloud_builder_aws(self) -> bool:
        """Check if the current cloudaccount builder is set to AWS type."""
        if not self.builder_stack:
            return False
        active = self.builder_stack[-1]
        if active.entity_name not in ("cloudaccount", "awsaccount"):
            return False
        if active.entity_name == "awsaccount":
            return True
        cloud_type = active.properties.get("cloud_type", "")
        return str(cloud_type).upper() == "AWS"

    def _extract_argparse_args(self, method: Any) -> str:
        """Inspect source of a do_* method and extract argparse argument flags.

        Args:
            method: The bound method to inspect.

        Returns:
            A formatted string of discovered arguments, e.g. "-p/--public, -r/--random".
        """
        try:
            source = inspect.getsource(method)
        except (OSError, TypeError):
            return ""

        # Match add_argument calls and extract flag names
        pattern = r"add_argument\(\s*(['\"].*?['\"](?:\s*,\s*['\"].*?['\"])*)"
        matches = re.findall(pattern, source)
        if not matches:
            return ""

        flags: list[str] = []
        for match in matches:
            # Extract individual string literals from the match
            args = re.findall(r"['\"]([^'\"]+)['\"]", match)
            if args:
                flags.append("/".join(args))

        return ", ".join(flags)

    def _scan_backends(self) -> Dict[str, Dict[str, str]]:
        """
        Dynamically scans backends/ and ai/providers/ for plugins.
        Extracts __category__ and __description__ metadata.
        """
        discovery: Dict[str, Dict[str, str]] = {}
        base_path = Path(__file__).parent

        scan_dirs = [
            ("wintermute.backends", base_path / "backends"),
            ("wintermute.ai.providers", base_path / "ai" / "providers"),
        ]

        for pkg_name, pkg_path in scan_dirs:
            if not pkg_path.exists():
                continue

            for py_file in pkg_path.glob("*.py"):
                if py_file.name == "__init__.py" or py_file.name.startswith("."):
                    continue

                mod_name = py_file.stem
                full_mod_path = f"{pkg_name}.{mod_name}"

                try:
                    # Dynamically import the module
                    mod = importlib.import_module(full_mod_path)

                    # Extract metadata
                    category = getattr(
                        mod,
                        "__category__",
                        "Exploits" if "cartridges" in str(py_file) else "Miscellaneous",
                    )
                    description = getattr(
                        mod,
                        "__description__",
                        "No documentation available for this neural link.",
                    )

                    discovery[mod_name] = {
                        "category": category,
                        "description": description,
                    }
                except Exception as e:
                    logger.warning(f"Failed to load metadata from {full_mod_path}: {e}")

        return discovery

    def display_banner(self) -> None:
        banner = r"""
  _      __.__        __                              __
 /  \    /  \__| _____/  |_  ___________  _____  __ ___/  |_  ____
 \   \/\/   /  |/    \   __\/ __ \_  __ \/     \|  |  \   __\/ __ \
  \        /|  |   |  \  | \  ___/|  | \/  Y Y  \  |  /|  | \  ___/
   \__/\  / |__|___|  /__|  \___  >__|  |__|_|  /____/ |__|  \___  >
        \/          \/          \/            \/                 \/

                    onoSendai Cyberspace Deck 7
        """
        self.rich_console.print(Panel(banner, border_style="bright_cyan", expand=False))
        self.rich_console.print(
            '[dim cyan]"The sky above the port was the color of television, '
            'tuned to a dead channel."[/]'
        )
        self.rich_console.print(
            f"[bold cyan]Jacked into:[/] {self.operation.operation_name}"
        )
        if self.current_cartridge_name:
            self.rich_console.print(
                f"[bold yellow]Active Cartridge:[/] {self.current_cartridge_name}"
            )
        self.rich_console.print("")

    def get_prompt_tokens(self) -> List[tuple[str, str]]:
        tokens: List[tuple[str, str]] = [("class:prompt", "onoSendai")]

        # Build hierarchical path
        current_ctx = self.context_stack[-1]
        has_operation = current_ctx in ("operation", "backend") or (
            current_ctx == "wintermute"
            and self.operation.operation_name != "default"
            and (self.builder_stack or self.current_cartridge_name)
        )

        # Show operation name when in any deeper context
        if has_operation or current_ctx == "operation":
            path_parts: list[str] = [self.operation.operation_name]

            # Walk builder_stack to append entity segments
            if hasattr(self, "builder_stack") and self.builder_stack:
                for ctx in self.builder_stack:
                    identifier = ctx.properties.get(
                        "hostname",
                        ctx.properties.get(
                            "name",
                            ctx.properties.get("uid", ""),
                        ),
                    )
                    if identifier:
                        path_parts.append(f"{ctx.entity_name}:{identifier}")
                    else:
                        path_parts.append(ctx.entity_name)

            tokens.append(("class:separator", " ["))
            tokens.append(("class:path", "/".join(path_parts)))
            tokens.append(("class:separator", "]"))

        # Show cartridge context after path
        if self.current_cartridge_name:
            tokens.append(("class:context", f" exploit({self.current_cartridge_name})"))
        # Show backend context
        elif current_ctx == "backend":
            tokens.append(("class:context", " backend"))

        tokens.append(("class:prompt", " > "))
        return tokens

    def __pt_formatted_text__(self) -> Any:
        return self.get_prompt_tokens()

    def update_completer(self) -> NestedCompleter:
        """Builds and updates the nested completer based on current state."""
        # 1. STRICT OVERRIDE: Check if Builder Stack is active
        if self.builder_stack:
            active_ctx = self.builder_stack[-1]
            target_cls = active_ctx.entity_class

            # For cloudaccount, resolve actual class based on cloud_type
            effective_cls = target_cls
            if (
                active_ctx.entity_name in ("cloudaccount",)
                and target_cls is CloudAccount
            ):
                cloud_type = active_ctx.properties.get("cloud_type", "")
                resolved = self.CLOUD_TYPE_MAP.get(str(cloud_type).lower())
                if resolved:
                    effective_cls = resolved

            # Dynamic 'set' suggestions using inspect.signature
            set_suggestions: Dict[str, Any] = {}
            if effective_cls:
                try:
                    sig = inspect.signature(effective_cls.__init__)
                    for name, param in sig.parameters.items():
                        if name in ["self", "args", "kwargs"]:
                            continue
                        set_suggestions[name] = None
                except Exception:
                    pass
            # Always offer cloud_type in cloudaccount builders
            if active_ctx.entity_name in ("cloudaccount",):
                set_suggestions["cloud_type"] = {k: None for k in self.CLOUD_TYPE_MAP}

            # Define commands ONLY valid inside the builder
            builder_commands: Dict[str, Any] = {
                "set": set_suggestions,
                "show": None,
                "save": None,
                "back": None,
                "help": None,
            }

            # Nested 'add' logic
            if active_ctx.entity_name == "device":
                builder_commands["add"] = {
                    "peripheral": {k: None for k in self.PERIPHERAL_MAP.keys()},
                    "processor": None,
                    "vulnerability": None,
                    "service": None,
                }
            elif active_ctx.entity_name == "service":
                builder_commands["add"] = {"vulnerability": None}
            elif active_ctx.entity_name == "pcie":
                builder_commands["add"] = {
                    "processor": None,
                    "memory": None,
                    "architecture": None,
                }
            elif active_ctx.entity_name in ("cloudaccount", "awsaccount"):
                if self._is_cloud_builder_aws():
                    builder_commands["add"] = {
                        "iamuser": None,
                        "iamrole": None,
                        "awsservice": None,
                        "awsuser": None,
                        "vulnerability": None,
                    }
                else:
                    builder_commands["add"] = {
                        "vulnerability": None,
                    }

            return NestedCompleter.from_nested_dict(builder_commands)

        current_context = self.context_stack[-1]

        # Common commands available everywhere
        common_commands: Dict[str, Any] = {
            "help": None,
            "exit": None,
            "back": None,
            "status": None,
            "vars": None,
            "workspace": {
                "switch": None,
            },
            "add": {
                "analyst": None,
                "device": None,
                "user": None,
                "service": None,
                "cloudaccount": None,
            },
            "edit": None,
            "delete": None,
        }

        # Gather dynamic completion data
        available_models: List[str] = []
        available_rags: List[str] = []
        if self.ai_router:
            try:
                provider = llms.get(self.ai_router.default_provider)
                available_models = [m.name for m in provider.list_models()]
                # Collect available RAG providers
                for name in llms.providers():
                    if name.startswith("rag-"):
                        available_rags.append(name)
            except Exception:
                pass

        catalog = self._scan_backends()
        backend_setup_options = {name: None for name in catalog.keys()}

        # Root Context Commands
        if current_context == "wintermute":
            base_commands: Dict[str, Any] = {
                **common_commands,
                "operation": {
                    "create": None,
                },
                # 'workspace' is now in common_commands
                "add": {
                    "analyst": None,
                    "device": None,
                    "user": None,
                    "service": None,
                    "cloudaccount": None,
                },
                "use": {
                    "load": {c: None for c in self.available_cartridges},
                    "unload": None,
                    "list": None,
                    **{c: None for c in self.available_cartridges},
                },
                "show": {
                    "options": None,
                    "commands": None,
                    "cartridges": None,
                    "info": None,
                    "status": None,
                },
                "ai": {
                    "model": {
                        "set": {m: None for m in available_models},
                        "list": None,
                    },
                    "rag": {
                        "list": None,
                        "use": {r: None for r in available_rags},
                        "off": None,
                        "scan": None,
                    },
                    "chat": None,
                },
                "backend": None,  # Enter backend submenu
                "tools": {
                    "load": None,
                    "list": None,
                },
            }

            # Dynamic lists for edit and delete command completion
            edit_targets: Dict[str, Any] = {
                "device": {d.hostname: None for d in self.operation.devices},
                "user": {u.uid: None for u in self.operation.users},
                "cloudaccount": {
                    a.name: None
                    for a in self.operation.cloud_accounts
                    if hasattr(a, "name")
                },
            }

            # Collect all nested objects for edit/delete
            all_devices = {d.hostname: None for d in self.operation.devices}
            all_users = {u.uid: None for u in self.operation.users}
            all_aws = {
                a.name: None for a in self.operation.awsaccounts if hasattr(a, "name")
            }

            # Collect peripherals
            all_peripherals: Dict[str, Any] = {}
            for d in self.operation.devices:
                for p in d.peripherals or []:
                    p_name = getattr(p, "name", None)
                    if p_name:
                        all_peripherals[f"{d.hostname}.peripherals.{p_name}"] = None

            # Collect services
            all_services: Dict[str, Any] = {}
            for d in self.operation.devices:
                for s in d.services or []:
                    s_name = getattr(s, "app", None)
                    if s_name:
                        all_services[f"{d.hostname}.services.{s_name}"] = None

            # Collect vulnerabilities
            all_vulns: Dict[str, Any] = {}
            for d in self.operation.devices:
                for v in d.vulnerabilities or []:
                    v_title = getattr(v, "title", None)
                    if v_title:
                        all_vulns[f"{d.hostname}.vulnerabilities.{v_title}"] = None

            # Collect cloud account nested objects
            all_cloud: Dict[str, Any] = {}
            for acc in self.operation.cloud_accounts:
                acc_name = getattr(acc, "name", None)
                if acc_name:
                    for u in acc.iamusers or []:
                        u_name = getattr(u, "username", None)
                        if u_name:
                            all_cloud[f"{acc_name}.iamusers.{u_name}"] = None
                    for r in acc.iamroles or []:
                        r_name = getattr(r, "role_name", None)
                        if r_name:
                            all_cloud[f"{acc_name}.iamroles.{r_name}"] = None

            # Combine all targets for delete command
            all_delete_targets: Dict[str, Any] = {
                **all_devices,
                **all_users,
                **all_aws,
                **all_peripherals,
                **all_services,
                **all_vulns,
                **all_cloud,
            }

            base_commands["edit"] = edit_targets
            base_commands["delete"] = all_delete_targets

            if self.current_cartridge_name:
                set_opts = {opt: None for opt in self.cartridge_options}
                # Merge instance self.options keys if available
                if self.current_cartridge_instance and hasattr(
                    self.current_cartridge_instance, "options"
                ):
                    inst_opts = self.current_cartridge_instance.options
                    if isinstance(inst_opts, dict):
                        for k in inst_opts:
                            if k not in set_opts:
                                set_opts[k] = None
                base_commands["set"] = set_opts
                base_commands["run"] = None
                # Dynamic commands from cartridge
                if self.current_cartridge_instance:
                    for name, _ in inspect.getmembers(
                        self.current_cartridge_instance, predicate=inspect.ismethod
                    ):
                        if name.startswith("do_"):
                            base_commands[name[3:]] = None

            return NestedCompleter.from_nested_dict(base_commands)

        # Backend Context Commands
        elif current_context == "backend":
            backend_commands: Dict[str, Any] = {
                **common_commands,
                "list": None,
                "available": None,
                "setup": backend_setup_options,
                "ai": {
                    "model": {
                        "set": {m: None for m in available_models},
                        "list": None,
                    },
                    "rag": {
                        "list": None,
                        "use": {r: None for r in available_rags},
                        "off": None,
                        "scan": None,
                    },
                    "chat": None,
                },
                "tools": {
                    "load": None,
                    "list": None,
                },
                "show": {
                    "options": None,
                    "commands": None,
                    "cartridges": None,
                },
                "use": {
                    "load": {c: None for c in self.available_cartridges},
                    "unload": None,
                    "list": None,
                    **{c: None for c in self.available_cartridges},
                },
            }
            return NestedCompleter.from_nested_dict(backend_commands)

        # Operation Context Commands
        elif current_context == "operation":
            op_commands: Dict[str, Any] = {
                **common_commands,
                "set": {
                    "name": None,
                    "start_date": None,
                    "end_date": None,
                    "ticket": None,
                },
                "save": None,
                "load": None,
                "delete": None,
                "ai": {
                    "model": {
                        "set": {m: None for m in available_models},
                        "list": None,
                    },
                    "rag": {
                        "list": None,
                        "use": {r: None for r in available_rags},
                        "off": None,
                        "scan": None,
                    },
                    "chat": None,
                },
                "tools": {
                    "load": None,
                    "list": None,
                },
                "show": {
                    "options": None,
                    "commands": None,
                    "cartridges": None,
                },
                "use": {
                    "load": {c: None for c in self.available_cartridges},
                    "unload": None,
                    "list": None,
                    **{c: None for c in self.available_cartridges},
                },
            }
            return NestedCompleter.from_nested_dict(op_commands)

        # Fallback
        return NestedCompleter.from_nested_dict(common_commands)

    # --- Global Commands ---

    def cmd_operation_create(self, name: str) -> None:
        self.operation = Operation(operation_name=name)
        self.rich_console.print(
            f"[*] New operation initialized... jacking in: [bold cyan]{name}[/]"
        )
        # Automatically enter the operation context
        self.cmd_operation_enter()

    def cmd_operation_enter(self) -> None:
        if self.context_stack[-1] != "operation":
            self.context_stack.append("operation")

    def cmd_operation_set(self, key: str, value: str) -> None:
        key = key.lower()
        if key == "name":
            self.operation.operation_name = value
        elif key == "start_date":
            self.operation.start_date = value
        elif key == "end_date":
            self.operation.end_date = value
        elif key == "ticket":
            self.operation.ticket = value
        else:
            self.rich_console.print(f"[red][!] Unknown property: {key}[/]")
            return
        self.rich_console.print(f"[*] Set {key} = {value}")

    def cmd_operation_save(self) -> None:
        if not self.operation.operation_name:
            self.rich_console.print("[red][!] Operation has no name![/]")
            return
        try:
            if self.operation.save():
                self.rich_console.print(
                    f"[bold green]✔[/] Saved operation: {self.operation.operation_name}"
                )
            else:
                self.rich_console.print("[red][!] Save failed (check logs).[/]")
        except Exception as e:
            self.rich_console.print(f"[red][!] Save error: {e}[/]")

    def cmd_operation_load(self, name: str) -> None:
        old_name = self.operation.operation_name
        self.operation.operation_name = name
        try:
            if self.operation.load():
                # Explicitly update _active to match the loaded operation
                Operation._active = self.operation
                self.rich_console.print(f"[bold green]✔[/] Loaded operation: {name}")
            else:
                self.rich_console.print(
                    f"[yellow][!] Could not load {name}, keeping empty context with name {name}.[/]"
                )
        except Exception as e:
            self.rich_console.print(f"[red][!] Load error: {e}[/]")
            self.operation.operation_name = old_name

    def cmd_operation_delete(self, name: str) -> None:
        try:
            backend = self.operation.backend
            if hasattr(backend, "delete"):
                if backend.delete(name):
                    self.rich_console.print(
                        f"[bold green]✔[/] Deleted operation: {name}"
                    )
                else:
                    self.rich_console.print(f"[red][!] Failed to delete: {name}[/]")
            else:
                self.rich_console.print(
                    "[red][!] Backend does not support deletion.[/]"
                )
        except Exception as e:
            self.rich_console.print(f"[red][!] Delete error: {e}[/]")

    def _format_value(self, value: Any) -> str:
        """Format a value for display in the status table.

        Args:
            value: The value to format.

        Returns:
            A formatted string representation of the value.
        """
        if isinstance(value, Enum):
            return value.name
        if isinstance(value, list):
            return f"[{len(value)} items]"
        if isinstance(value, dict):
            return f"{{{len(value)} keys}}"
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        if value is None:
            return "[dim]None[/dim]"
        return str(value)

    def cmd_status(self) -> None:
        """Render a dynamic status tree of the current operation state."""
        # Check if there's an active operation
        if Operation._active is None:
            self.rich_console.print(
                Panel(
                    "[bold red]NO ACTIVE OPERATION — FLATLINE[/bold red]\n"
                    "Create an operation with 'operation create <name>'",
                    title="Status",
                    border_style="red",
                )
            )
            return

        op = Operation._active

        # Root Node
        root = Tree(
            f"[bold cyan]Operation: {op.operation_name}[/] [dim](ID: {op.operation_id})[/]"
        )

        # Branch: Analysts
        analysts_branch = root.add(f"[bold magenta]Analysts[/] ({len(op.analysts)})")
        for a in op.analysts:
            a_node = analysts_branch.add(f"[green]{a.name}[/] [dim]({a.userid})[/]")
            # Show analyst state table
            a_state = get_visible_state(a)
            if a_state:
                a_table = Table(show_header=True, header_style="bold cyan")
                a_table.add_column("SIGNAL", style="cyan")
                a_table.add_column("VALUE", style="bright_green")
                for key, val in a_state.items():
                    a_table.add_row(key, self._format_value(val))
                a_node.add(a_table)

        # Branch: Devices
        devices_branch = root.add(f"[bold magenta]Devices[/] ({len(op.devices)})")
        for d in op.devices:
            d_node = devices_branch.add(f"[green]{d.hostname}[/] [dim]({d.ipaddr})[/]")

            # Show Peripherals
            if d.peripherals:
                peri_branch = d_node.add(f"[blue]Peripherals[/] ({len(d.peripherals)})")
                for p in d.peripherals:
                    p_name = getattr(p, "name", "Unknown")
                    p_type = p.__class__.__name__
                    p_node = peri_branch.add(f"[cyan]{p_name}[/] [dim]({p_type})[/]")
                    # Show peripheral state table
                    p_state = get_visible_state(p)
                    if p_state:
                        p_table = Table(show_header=True, header_style="bold cyan")
                        p_table.add_column("SIGNAL", style="cyan")
                        p_table.add_column("VALUE", style="bright_green")
                        for key, val in p_state.items():
                            p_table.add_row(key, self._format_value(val))
                        p_node.add(p_table)

                    # Show Vulnerabilities on peripheral
                    if hasattr(p, "vulnerabilities") and p.vulnerabilities:
                        vuln_branch = p_node.add(
                            f"[red]Vulnerabilities[/] ({len(p.vulnerabilities)})"
                        )
                        for v in p.vulnerabilities:
                            vuln_branch.add(
                                f"[yellow]{v.title}[/] [dim](CVSS: {v.cvss})[/]"
                            )

            # Show Services
            if d.services:
                svc_branch = d_node.add(f"[yellow]Services[/] ({len(d.services)})")
                for s in d.services:
                    svc_node = svc_branch.add(
                        f"[green]{s.portNumber}/{s.protocol}[/] [dim]({s.app})[/]"
                    )
                    # Show service state table
                    s_state = get_visible_state(s)
                    if s_state:
                        s_table = Table(show_header=True, header_style="bold cyan")
                        s_table.add_column("SIGNAL", style="cyan")
                        s_table.add_column("VALUE", style="bright_green")
                        for key, val in s_state.items():
                            s_table.add_row(key, self._format_value(val))
                        svc_node.add(s_table)

            # Show Vulnerabilities
            if d.vulnerabilities:
                vuln_branch = d_node.add(
                    f"[red]Vulnerabilities[/] ({len(d.vulnerabilities)})"
                )
                for v in d.vulnerabilities:
                    vuln_branch.add(f"[yellow]{v.title}[/] [dim](CVSS: {v.cvss})[/]")

        # Branch: Users
        users_branch = root.add(f"[bold magenta]Users[/] ({len(op.users)})")
        for u in op.users:
            u_node = users_branch.add(f"[green]{u.uid}[/]")
            # Show user state table
            u_state = get_visible_state(u)
            if u_state:
                u_table = Table(show_header=True, header_style="bold cyan")
                u_table.add_column("SIGNAL", style="cyan")
                u_table.add_column("VALUE", style="bright_green")
                for key, val in u_state.items():
                    u_table.add_row(key, self._format_value(val))
                u_node.add(u_table)

        # Branch: Cloud Accounts
        cloud_branch = root.add(
            f"[bold magenta]Cloud Accounts[/] ({len(op.cloud_accounts)})"
        )
        for acc in op.cloud_accounts:
            name = getattr(acc, "name", "Unknown")
            aid = getattr(acc, "account_id", "No ID")
            acc_node = cloud_branch.add(f"[green]{name}[/] [dim]({aid})[/]")
            # Show cloud account state table
            acc_state = get_visible_state(acc)
            if acc_state:
                acc_table = Table(show_header=True, header_style="bold cyan")
                acc_table.add_column("SIGNAL", style="cyan")
                acc_table.add_column("VALUE", style="bright_green")
                for key, val in acc_state.items():
                    acc_table.add_row(key, self._format_value(val))
                acc_node.add(acc_table)

        # Branch: Test Plans
        if op.test_plans:
            test_plans_branch = root.add(
                f"[bold magenta]Test Plans[/] ({len(op.test_plans)})"
            )
            for tp in op.test_plans:
                test_plans_branch.add(f"[cyan]{tp.code}[/] [dim]({tp.name})[/]")

        self.rich_console.print(root)

    def cmd_workspace_switch(self, name: str) -> None:
        # Legacy support
        self.cmd_operation_load(name)

    def cmd_add_analyst(self, name: str, userid: str, email: str) -> None:
        if self.operation.addAnalyst(name, userid, email):
            self.rich_console.print(f"[+] Added analyst: {name} ({userid})")

    def cmd_add_device(self, hostname: str, ip: str = "127.0.0.1") -> None:
        if self.operation.addDevice(hostname, ipaddr=ip):
            self.rich_console.print(f"[+] Added device: {hostname} ({ip})")

    def cmd_add_user(self, uid: str, name: str, email: str) -> None:
        if self.operation.addUser(uid, name, email, teams=[]):
            self.rich_console.print(f"[+] Added user: {uid}")

    def cmd_add_service(self, device_hostname: str, port: str, app: str) -> None:
        device = self.operation.getDeviceByHostname(device_hostname)
        if device:
            if device.addService(portNumber=int(port), app=app):
                self.rich_console.print(
                    f"[+] Added service {app} on {device_hostname}:{port}"
                )
        else:
            self.rich_console.print(f"[red][!] Device {device_hostname} not found.[/]")

    def cmd_add_cloudaccount(self, name: str, account_id: str) -> None:
        if self.operation.addCloudAccount(
            name, cloud_type="AWS", account_id=account_id
        ):
            self.rich_console.print(f"[+] Added Cloud Account: {name} ({account_id})")

    def cmd_add_awsaccount(self, name: str, account_id: str) -> None:
        self.cmd_add_cloudaccount(name, account_id)

    def cmd_edit(self, path: str) -> None:
        """Enters builder context populated with existing entity data using full path resolution.

        Args:
            path: Path to the object (e.g., "gateway_node", "gateway_node.peripherals.uart0")
        """
        # Use _resolve_path to find the object
        target_obj = self._resolve_path(path)

        if target_obj is None:
            self.rich_console.print(
                f"[red][!] Could not find object at path: {path}[/]"
            )
            return

        # Determine entity type from object class
        obj_type = target_obj.__class__.__name__.lower()

        # Extract properties using get_visible_state
        props = get_visible_state(target_obj)

        # Enter Builder with the resolved object
        cls = self.ENTITY_CLASSES.get(obj_type)
        ctx = BuilderContext(obj_type, entity_class=cls)
        ctx.properties = props
        # Store original object reference for edit mode
        ctx._original_object = target_obj
        self.builder_stack.append(ctx)
        self.rich_console.print(
            f"[*] Editing object at path: [bold cyan]{path}[/] (Builder Mode)"
        )

    def cmd_delete(self, path: str) -> None:
        """Delete an object from the operation using full path resolution.

        Args:
            path: Path to the object (e.g., "gateway_node", "gateway_node.peripherals.uart0")
        """
        # Use _resolve_path to find the object
        target_obj = self._resolve_path(path)

        if target_obj is None:
            # _resolve_path already prints the error details
            return

        # Get object type and identifier for display
        obj_type = target_obj.__class__.__name__
        obj_id = (
            getattr(target_obj, "hostname", None)
            or getattr(target_obj, "uid", None)
            or getattr(target_obj, "name", None)
            or getattr(target_obj, "app", None)
            or getattr(target_obj, "title", None)
            or getattr(target_obj, "username", None)
            or getattr(target_obj, "role_name", None)
            or str(target_obj)
        )

        # Safety confirmation
        confirm = (
            input(f"Are you sure you want to delete {obj_type} '{obj_id}'? (y/N): ")
            .strip()
            .lower()
        )
        if confirm != "y":
            self.rich_console.print("[yellow]Delete cancelled.[/]")
            return

        # Find parent container and remove the object
        success = self._remove_object_from_parent(path, target_obj)

        if success:
            self.rich_console.print(f"[bold green]✔[/] Deleted {obj_type}: {obj_id}")
        else:
            self.rich_console.print(
                f"[red][!] Failed to delete {obj_type}: {obj_id}[/]"
            )

    def _remove_object_from_parent(self, path: str, target_obj: Any) -> bool:
        """Remove an object from its parent container using path resolution.

        Args:
            path: Path to the object
            target_obj: The object to remove

        Returns:
            True if removal was successful, False otherwise
        """
        # We reuse the same parsing logic as _resolve_path
        try:
            normalized = ""
            in_quote = False
            quote_char = ""
            for char in path:
                if char in ('"', "'"):
                    if not in_quote:
                        in_quote = True
                        quote_char = char
                    elif char == quote_char:
                        in_quote = False
                if not in_quote and char in (".", "/"):
                    normalized += " "
                else:
                    normalized += char
            parts = shlex.split(normalized)
        except Exception:
            return False

        if not parts:
            return False

        # Handle explicit typing (e.g., "device.hostname.peripheral.name")
        if parts[0] in (
            "analyst",
            "device",
            "cloudaccount",
            "cloud_account",
            "user",
            "awsaccount",
            "peripheral",
            "service",
        ):
            parts = parts[1:]

        if not parts:
            return False

        if len(parts) == 1:
            # Root level object - remove from operation
            if target_obj in self.operation.analysts:
                self.operation.analysts.remove(target_obj)
                return True
            if target_obj in self.operation.devices:
                self.operation.devices.remove(target_obj)
                return True
            if target_obj in self.operation.users:
                self.operation.users.remove(target_obj)
                return True
            if target_obj in self.operation.cloud_accounts:
                self.operation.cloud_accounts.remove(target_obj)
                return True
            return False

        # Nested object - find parent path
        # We reconstruct the parent path by joining all parts except the last one
        # This is safe because we're using the same shlex-split parts
        parent_parts = parts[:-1]

        # Filter out noise/container words from the end of parent_parts if they were explicitly provided
        # e.g. "host.peripherals.uart" -> parent is "host", but path could be "host.peripherals"
        while parent_parts and parent_parts[-1] in (
            "peripherals",
            "services",
            "vulnerabilities",
            "iamusers",
            "iamroles",
            "processor",
            "memory",
            "architecture",
        ):
            parent_parts.pop()

        if not parent_parts:
            # If after stripping container words we have nothing, it was likely root-level anyway
            return self._remove_object_from_parent(parts[-1], target_obj)

        parent_path = ".".join([f'"{p}"' if " " in p else p for p in parent_parts])
        parent_obj = self._resolve_path(parent_path)

        if parent_obj is None:
            self.rich_console.print(
                "[red][!] Could not identify parent container for removal.[/]"
            )
            return False

        # Try to remove from common list attributes
        for attr_name in [
            "peripherals",
            "services",
            "vulnerabilities",
            "iamusers",
            "iamroles",
        ]:
            if hasattr(parent_obj, attr_name):
                lst = getattr(parent_obj, attr_name)
                if isinstance(lst, list) and target_obj in lst:
                    lst.remove(target_obj)
                    return True

        # Handle direct assignments (processor, memory, etc.)
        for attr_name in ["processor", "memory", "architecture"]:
            if getattr(parent_obj, attr_name, None) is target_obj:
                setattr(parent_obj, attr_name, None)
                return True

        return False

    # --- Builder Context ---

    def cmd_builder_set(self, key: str, value: str) -> None:
        """Sets a property in the current builder context."""
        if not self.builder_stack:
            return

        active_builder = self.builder_stack[-1]

        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif len(value) >= 2 and value.startswith("'") and value.endswith("'"):
            value = value[1:-1]

        # Simple type inference - use a Union type for the inferred value
        val: str | int | bool
        if value.isdigit():
            val = int(value)
        elif value.lower() == "true":
            val = True
        elif value.lower() == "false":
            val = False
        else:
            val = value

        active_builder.properties[key] = val
        self.rich_console.print(f"[*] Set {key} = {val}")

        # Dynamic cloud_type switching for cloudaccount builders
        if (
            key == "cloud_type"
            and active_builder.entity_name in ("cloudaccount",)
            and isinstance(val, str)
        ):
            resolved_cls = self.CLOUD_TYPE_MAP.get(val.lower())
            if resolved_cls:
                active_builder.entity_class = resolved_cls
                self.rich_console.print(
                    f"[*] Cloud account type set to [bold cyan]{val.upper()}[/] "
                    f"— attributes updated"
                )
            else:
                self.rich_console.print(
                    f"[yellow][!] Unknown cloud type '{val}'. "
                    f"Available: {', '.join(self.CLOUD_TYPE_MAP.keys())}[/]"
                )

    def cmd_builder_show(self) -> None:
        """Shows the current builder state."""
        if not self.builder_stack:
            self.rich_console.print("[red]No active builder.[/]")
            return

        active_builder = self.builder_stack[-1]
        target = active_builder.entity_name
        table = Table(title=f"Building: {target}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for k, v in active_builder.properties.items():
            # If value is a list (e.g. nested peripherals), show items
            if isinstance(v, list):
                if v:
                    # Detailed list view
                    items_str = []
                    for item in v:
                        if hasattr(item, "name"):
                            items_str.append(f"- {item.name}")
                        elif hasattr(item, "hostname"):
                            items_str.append(f"- {item.hostname}")
                        elif hasattr(item, "title"):
                            items_str.append(f"- {item.title}")
                        elif hasattr(item, "uid"):
                            items_str.append(f"- {item.uid}")
                        else:
                            items_str.append(f"- {str(item)}")

                    val_str = "\n".join(items_str)
                else:
                    val_str = "[]"
            else:
                val_str = str(v)
            table.add_row(k, val_str)

        self.rich_console.print(table)

    def cmd_builder_save(self) -> None:
        """Commits the built entity to the operation or parent builder."""
        if not self.builder_stack:
            return

        # Pop current builder to process it
        active_builder = self.builder_stack[-1]
        target = active_builder.entity_name
        data = active_builder.properties
        cls = active_builder.entity_class

        # Check if this is an edit mode (original object exists)
        original_obj = active_builder._original_object

        try:
            # 1. Instantiate Object if class is mapped
            entity_obj = None
            if cls:
                # Filter unknown kwargs to avoid __init__ errors
                sig = inspect.signature(cls.__init__)
                valid_kwargs = {
                    k: v
                    for k, v in data.items()
                    if k in sig.parameters
                    and sig.parameters[k].kind
                    in (
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.KEYWORD_ONLY,
                    )
                }
                entity_obj = cls(**valid_kwargs)
                # Manually set attributes that were not in __init__ but in data
                for k, v in data.items():
                    if k not in valid_kwargs and not k.startswith("_"):
                        setattr(entity_obj, k, v)
            else:
                entity_obj = data

            # 2. In-Place Editing Logic
            if original_obj:
                if entity_obj:
                    # Use the library's merge logic to update the original instance
                    self.operation._merge_attributes(original_obj, entity_obj)
                    self.rich_console.print(
                        f"[bold green]✔[/] Updated existing {target} in-place."
                    )
                self.cmd_back()
                return

            # 3. Check if Root or Nested (for NEW objects)
            if len(self.builder_stack) == 1:
                # --- ROOT LEVEL SAVE ---
                if not entity_obj:
                    self.rich_console.print(
                        f"[red][!] Could not instantiate class for {target}.[/]"
                    )
                    return

                success = False
                if target == "analyst" and isinstance(entity_obj, Analyst):
                    if self.operation.addAnalyst(
                        name=entity_obj.name,
                        userid=entity_obj.userid,
                        email=entity_obj.email or "",
                    ):
                        self.rich_console.print(
                            f"[bold green]✔[/] Saved Analyst: {entity_obj.name} ({entity_obj.userid})"
                        )
                        success = True
                elif target == "device" and isinstance(entity_obj, Device):
                    if self.operation.addDevice(
                        hostname=entity_obj.hostname,
                        ipaddr=entity_obj.ipaddr,
                        macaddr=entity_obj.macaddr,
                        operatingsystem=entity_obj.operatingsystem,
                        fqdn=entity_obj.fqdn,
                        services=getattr(entity_obj, "services", []),
                        peripherals=getattr(entity_obj, "peripherals", []),
                        vulnerabilities=getattr(entity_obj, "vulnerabilities", []),
                    ):
                        self.rich_console.print(
                            f"[bold green]✔[/] Saved Device: {entity_obj.hostname}"
                        )
                        success = True
                elif target == "user" and isinstance(entity_obj, User):
                    if self.operation.addUser(
                        uid=entity_obj.uid,
                        name=entity_obj.name,
                        email=entity_obj.email,
                        teams=entity_obj.teams,
                        vulnerabilities=getattr(entity_obj, "vulnerabilities", []),
                    ):
                        self.rich_console.print(
                            f"[bold green]✔[/] Saved User: {entity_obj.uid}"
                        )
                        success = True
                elif target in ("cloudaccount", "awsaccount") and isinstance(
                    entity_obj, (CloudAccount, AWSAccount)
                ):
                    # Determine the actual cloud_type from properties or entity
                    save_cloud_type = data.get(
                        "cloud_type", getattr(entity_obj, "cloud_type", "generic")
                    )
                    save_kwargs: dict[str, Any] = {
                        "name": entity_obj.name,
                        "cloud_type": str(save_cloud_type),
                        "vulnerabilities": getattr(entity_obj, "vulnerabilities", []),
                    }
                    if isinstance(entity_obj, AWSAccount):
                        save_kwargs.update(
                            {
                                "account_id": entity_obj.account_id,
                                "iamusers": getattr(entity_obj, "iamusers", []),
                                "iamroles": getattr(entity_obj, "iamroles", []),
                                "users": getattr(entity_obj, "users", []),
                                "services": getattr(entity_obj, "services", []),
                            }
                        )
                    if self.operation.addCloudAccount(**save_kwargs):
                        self.rich_console.print(
                            f"[bold green]✔[/] Saved Cloud Account: {entity_obj.name}"
                        )
                        success = True
                elif target == "service" and isinstance(entity_obj, Service):
                    dev_host = data.get("device_hostname")
                    if dev_host:
                        dev = self.operation.getDeviceByHostname(str(dev_host))
                        if dev:
                            dev.services.append(entity_obj)
                            self.rich_console.print(
                                f"[bold green]✔[/] Added Service to {dev_host}"
                            )
                            success = True
                        else:
                            self.rich_console.print(
                                f"[red][!] Device {dev_host} not found[/]"
                            )
                    else:
                        self.rich_console.print(
                            "[red][!] Root service requires 'device_hostname' property to attach.[/]"
                        )
                else:
                    # Generic fallback for other types
                    self.rich_console.print(
                        f"[red][!] Cannot save {target} at root level (unsupported type).[/]"
                    )
                    return

                if success:
                    self.cmd_back()

            else:
                # --- NESTED LEVEL SAVE (NEW objects) ---
                parent_builder = self.builder_stack[-2]
                field_name = active_builder.parent_list_name or target

                # Determine if field is a list or scalar
                is_list_field = False
                if active_builder.parent_list_name:
                    is_list_field = True
                elif parent_builder.entity_class:
                    try:
                        sig = inspect.signature(parent_builder.entity_class.__init__)
                        if field_name in sig.parameters:
                            param = sig.parameters[field_name]
                            type_str = str(param.annotation)
                            if any(
                                x in type_str.lower()
                                for x in ["list", "sequence", "iterable"]
                            ):
                                is_list_field = True
                    except Exception:
                        pass

                if is_list_field:
                    if field_name not in parent_builder.properties:
                        parent_builder.properties[field_name] = []
                    parent_builder.properties[field_name].append(entity_obj)
                    self.rich_console.print(
                        f"[bold green]✔[/] Attached new {target} to parent list '{field_name}'."
                    )
                else:
                    parent_builder.properties[field_name] = entity_obj
                    self.rich_console.print(
                        f"[bold green]✔[/] Set parent field '{field_name}' = {target}"
                    )

                self.cmd_back()

        except Exception as e:
            self.rich_console.print(f"[red][!] Builder error: {e}[/]")
            logger.exception("Builder save error")

    def _resolve_path(self, path: str) -> Any:
        """Resolve a path string to an object in the operation tree.

        Supports complex identifiers with quotes and spaces, and deep-tree traversal.

        Args:
            path: Path string (e.g., gateway.peripherals."debug console")

        Returns:
            The resolved object, or None if not found.
        """
        if not path:
            return None

        # Replace slashes with dots but preserve quotes.
        # Use shlex.split for robust parsing of quoted identifiers.
        try:
            normalized = ""
            in_quote = False
            quote_char = ""
            for char in path:
                if char in ('"', "'"):
                    if not in_quote:
                        in_quote = True
                        quote_char = char
                    elif char == quote_char:
                        in_quote = False
                if not in_quote and char in (".", "/"):
                    normalized += " "
                else:
                    normalized += char
            parts = shlex.split(normalized)
        except Exception as e:
            logger.debug(f"Path parsing failed: {e}")
            return None

        if not parts:
            return None

        # Handle explicit typing prefixes (e.g., "device.hostname")
        type_prefixes = (
            "analyst",
            "device",
            "cloudaccount",
            "cloud_account",
            "user",
            "awsaccount",
            "peripheral",
            "service",
        )
        if parts[0].lower() in type_prefixes:
            parts = parts[1:]

        if not parts:
            return None

        # 1. Root Level Search
        current: Any = None
        root_name = parts[0]

        # Search analysts (userid or name)
        for a in self.operation.analysts:
            if a.userid == root_name or a.name == root_name:
                current = a
                break
        # Search devices (hostname)
        if current is None:
            for d in self.operation.devices:
                if d.hostname == root_name:
                    current = d
                    break
        # Search users (uid)
        if current is None:
            for u in self.operation.users:
                if u.uid == root_name:
                    current = u
                    break
        # Search cloud accounts (name/id)
        if current is None:
            for acc in self.operation.cloud_accounts:
                if (
                    getattr(acc, "name", "") == root_name
                    or getattr(acc, "account_id", "") == root_name
                ):
                    current = acc
                    break

        if current is None:
            self.rich_console.print(f"[red][!] Root object '{root_name}' not found.[/]")
            return None

        # 2. Traversal
        container_keywords = (
            "peripherals",
            "services",
            "vulnerabilities",
            "iamusers",
            "iamroles",
            "processor",
            "memory",
            "architecture",
            "desktops",
            "users",
            "analysts",
            "test_plans",
            "test_runs",
        )

        for i in range(1, len(parts)):
            part = parts[i]
            if not current:
                break

            # If the part is just a container keyword, skip it to look inside it
            if part.lower() in container_keywords:
                # If it's the last part, return the list itself
                if i == len(parts) - 1:
                    return getattr(current, part, None)
                continue

            parent = current
            found_obj = None

            # --- Check lists ---
            lists_to_search = [
                "peripherals",
                "services",
                "vulnerabilities",
                "iamusers",
                "iamroles",
                "users",
                "desktops",
            ]

            for attr in lists_to_search:
                if hasattr(parent, attr):
                    lst = getattr(parent, attr)
                    if isinstance(lst, list):
                        for item in lst:
                            # Match by various identifier attributes
                            if (
                                getattr(item, "name", None) == part
                                or getattr(item, "app", None) == part
                                or str(getattr(item, "portNumber", "")) == part
                                or getattr(item, "title", None) == part
                                or getattr(item, "username", None) == part
                                or getattr(item, "role_name", None) == part
                                or getattr(item, "uid", None) == part
                                or getattr(item, "hostname", None) == part
                            ):
                                found_obj = item
                                break
                if found_obj:
                    break

            if found_obj is not None:
                current = found_obj
            else:
                parent_id = (
                    getattr(parent, "hostname", None)
                    or getattr(parent, "uid", None)
                    or getattr(parent, "name", None)
                    or str(parent)
                )
                self.rich_console.print(
                    f"[red][!] '{part}' not found under {parent.__class__.__name__} '{parent_id}'.[/]"
                )
                return None

        return current

    def cmd_vars(self, path: str) -> None:
        """Display visible state variables for an object at the given path.

        Args:
            path: Path to the object (e.g., "gateway_node/peripherals/uart0")
        """
        obj = self._resolve_path(path)

        if obj is None:
            self.rich_console.print(f"[red][!] Unknown target: {path}[/]")
            return

        # Use get_visible_state to extract variables
        state = get_visible_state(obj)

        if not state:
            self.rich_console.print(f"[yellow][!] No visible state for: {path}[/]")
            return

        # Display in a table
        table = Table(title=f"Variables: {path}")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")

        for key, value in state.items():
            table.add_row(key, self._format_value(value))

        self.rich_console.print(table)

    def cmd_add_enter(
        self,
        entity_type: str,
        cls: Optional[Type[Any]] = None,
        parent_list: Optional[str] = None,
    ) -> None:
        """Enters the builder context for a specific entity."""
        if not cls:
            cls = self.ENTITY_CLASSES.get(entity_type)

        ctx = BuilderContext(
            entity_type, entity_class=cls, parent_list_name=parent_list
        )
        self.builder_stack.append(ctx)
        self.rich_console.print(f"[*] Constructing {entity_type} node...")

    def cmd_back(self) -> None:
        """Pops the current context from the stack."""
        if len(self.context_stack) > 1:
            self.context_stack.pop()

        # Handle Builder Stack
        if self.builder_stack:
            self.builder_stack.pop()
        elif self.current_cartridge_name:
            # If in root but have a cartridge loaded, unload it
            self.current_cartridge_name = None
            self.current_cartridge_instance = None
            self.cartridge_options = {}
        else:
            # Already at root
            pass

    # --- Local Context (Cartridge) ---

    def cmd_use(self, *args: str) -> None:
        """Sub-menu dispatcher for cartridge management."""
        if not args:
            # Bare 'use' — show sub-menu help
            table = Table(title="use — Cartridge Management")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row("use list", "List available cartridges")
            table.add_row("use load <name>", "Load a cartridge")
            table.add_row("use unload", "Unload current cartridge")
            table.add_row("use <name>", "Load a cartridge (shorthand)")
            self.rich_console.print(table)
            return

        sub = args[0].lower()
        if sub == "list":
            self._cmd_use_list()
        elif sub == "unload":
            self._cmd_use_unload()
        elif sub == "load" and len(args) >= 2:
            self._cmd_use_load(args[1])
        else:
            # Backward compat: treat as cartridge name
            self._cmd_use_load(sub)

    def _cmd_use_list(self) -> None:
        """List available cartridges with loaded status."""
        table = Table(title="Available Cartridges")
        table.add_column("Name", style="cyan")
        table.add_column("Status", style="green")

        for c in self.available_cartridges:
            if c == self.current_cartridge_name:
                table.add_row(c, "[bold green]LOADED[/]")
            else:
                table.add_row(c, "available")

        self.rich_console.print(table)

    def _cmd_use_unload(self) -> None:
        """Unload the current cartridge."""
        if not self.current_cartridge_name:
            self.rich_console.print("[yellow][!] No cartridge loaded.[/]")
            return
        name = self.current_cartridge_name
        self.current_cartridge_name = None
        self.current_cartridge_instance = None
        self.cartridge_options = {}
        self.rich_console.print(f"[*] Cartridge unloaded: {name}")

    def _cmd_use_load(self, cartridge_name: str) -> None:
        """Load a cartridge by name, introspect options and instantiate."""
        if cartridge_name not in self.available_cartridges:
            self.rich_console.print(
                f"[red][!] Cartridge {cartridge_name} not found.[/]"
            )
            return

        try:
            module = importlib.import_module(f"wintermute.cartridges.{cartridge_name}")
            importlib.reload(module)
            cls = self._find_primary_class(module, cartridge_name)

            if not cls:
                self.rich_console.print(
                    f"[red][!] Could not find cartridge class in {cartridge_name}[/]"
                )
                return

            self.current_cartridge_name = cartridge_name

            # Introspect options from __init__
            self.cartridge_options = {}
            sig = inspect.signature(cls.__init__)
            for name, param in sig.parameters.items():
                if name in ["self", "transport"]:
                    continue
                default = (
                    param.default
                    if param.default is not inspect.Parameter.empty
                    else None
                )
                self.cartridge_options[name] = default

            # Attempt to instantiate at load time for do_*/self.options discovery
            try:
                self.current_cartridge_instance = cls(**self.cartridge_options)
            except Exception:
                self.current_cartridge_instance = None

            self.rich_console.print(
                f"[*] ICE-breaker loaded: [bold yellow]{cartridge_name}[/]"
            )
        except Exception as e:
            self.rich_console.print(f"[red][!] Error loading cartridge: {e}[/]")

    def cmd_set(self, option: str, value: str) -> None:
        if not self.current_cartridge_name:
            self.rich_console.print(
                "[red][!] No cartridge selected. Use 'use <cartridge>' first.[/]"
            )
            return

        # Try to cast value
        cast_val: str | int | bool = value
        if value.isdigit():
            cast_val = int(value)
        elif value.lower() in ["true", "false"]:
            cast_val = value.lower() == "true"

        # Check __init__ options first
        if option in self.cartridge_options:
            self.cartridge_options[option] = cast_val
            self.rich_console.print(f"{option} => {value}")
            return

        # Check instance self.options (e.g. tpm20 pattern)
        if self.current_cartridge_instance and hasattr(
            self.current_cartridge_instance, "options"
        ):
            inst_opts = self.current_cartridge_instance.options
            if isinstance(inst_opts, dict) and option in inst_opts:
                opt_data = inst_opts[option]
                if isinstance(opt_data, dict):
                    opt_data["value"] = cast_val
                else:
                    inst_opts[option] = cast_val
                self.rich_console.print(f"{option} => {value}")
                return

        self.rich_console.print(f"[red][!] Unknown option: {option}[/]")

    def cmd_run(self) -> None:
        if not self.current_cartridge_name:
            self.rich_console.print("[red][!] No cartridge selected.[/]")
            return

        try:
            module = importlib.import_module(
                f"wintermute.cartridges.{self.current_cartridge_name}"
            )
            cls = self._find_primary_class(module, self.current_cartridge_name)
            if not cls:
                self.rich_console.print(
                    f"[red][!] Could not find class for {self.current_cartridge_name}[/]"
                )
                return

            # Instantiate with options
            self.current_cartridge_instance = cls(**self.cartridge_options)

            if self.current_cartridge_instance and hasattr(
                self.current_cartridge_instance, "run"
            ):
                self.rich_console.print(
                    f"[*] Executing ICE-breaker: {self.current_cartridge_name}..."
                )
                self.current_cartridge_instance.run()
            else:
                self.rich_console.print(
                    f"[*] Cartridge {self.current_cartridge_name} instantiated. Use dynamic commands to interact."
                )
        except Exception as e:
            self.rich_console.print(f"[red][!] Execution error: {e}[/]")

    # --- Information & Help ---

    def cmd_show_current_context(self) -> None:
        """Display the current operation's visible state in a Rich table."""
        if Operation._active is None:
            self.cmd_status()
            return

        state = get_visible_state(self.operation)
        if not state:
            self.rich_console.print(
                "[yellow]No visible state for current operation.[/]"
            )
            return

        table = Table(title=f"Operation: {self.operation.operation_name}")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")

        for key, value in state.items():
            table.add_row(key, self._format_value(value))

        self.rich_console.print(table)

    def show_options(self) -> None:
        if not self.current_cartridge_name:
            self.rich_console.print("[red][!] No cartridge selected.[/]")
            return

        table = Table(title=f"Module options ({self.current_cartridge_name})")
        table.add_column("Name", style="cyan")
        table.add_column("Current Setting", style="green")
        table.add_column("Description", style="white")

        shown_keys: set[str] = set()
        for opt, val in self.cartridge_options.items():
            table.add_row(opt, str(val), "")
            shown_keys.add(opt)

        # Show instance self.options (e.g. tpm20 pattern: {key: {value, description}})
        if self.current_cartridge_instance and hasattr(
            self.current_cartridge_instance, "options"
        ):
            inst_opts = self.current_cartridge_instance.options
            if isinstance(inst_opts, dict):
                for key, opt_data in inst_opts.items():
                    if key in shown_keys:
                        continue
                    if isinstance(opt_data, dict):
                        val = str(opt_data.get("value", ""))
                        desc = str(opt_data.get("description", ""))
                    else:
                        val = str(opt_data)
                        desc = ""
                    table.add_row(key, val, desc)

        self.rich_console.print(table)

    def show_commands(self, topic: Optional[str] = None) -> None:
        current_context = self.context_stack[-1]

        # 0. Builder Context Help
        if self.builder_stack:
            active = self.builder_stack[-1].entity_name
            table = Table(title=f"Construct // {active}")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row("set <key> <val>", "Set property value")
            table.add_row("show", "Show current properties")
            table.add_row("save", "Commit and create entity")
            if active == "device":
                table.add_row("add peripheral <type>", "Add a nested peripheral")
                table.add_row("add service", "Add a service to device")
                table.add_row("add processor", "Add a processor to device")
                table.add_row("add memory", "Add memory to device")
                table.add_row("add architecture", "Add architecture to device")
            if active == "pcie":
                table.add_row("add processor", "Add a processor")
                table.add_row("add memory", "Add memory")
                table.add_row("add architecture", "Add architecture")
            if active in ("cloudaccount", "awsaccount"):
                table.add_row(
                    "set cloud_type <type>",
                    "Set cloud provider (aws, generic)",
                )
                if self._is_cloud_builder_aws():
                    table.add_row("add iamuser", "Add an IAM user")
                    table.add_row("add iamrole", "Add an IAM role")
                    table.add_row("add awsservice", "Add an AWS service")
                    table.add_row("add awsuser", "Add an AWS user")
                table.add_row("add vulnerability", "Add a finding")
            if active in ["service", "peripheral", "device"]:
                table.add_row("add vulnerability", "Add a finding")
            table.add_row("status", "Show operation status tree")
            table.add_row("vars <path>", "Inspect object variables")
            table.add_row("help", "Show this help")
            table.add_row("back", "Discard and return")
            self.rich_console.print(table)
            return

        # 1. Backend Context Help
        if current_context == "backend":
            table = Table(title="Backend Neural Interface")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row("list", "Show active backend connections")
            table.add_row("available", "List supported backend types")
            table.add_row("setup <type>", "Configure a new backend interface")
            table.add_row("status", "Show operation status tree")
            table.add_row("vars <path>", "Inspect object variables")
            table.add_row("ai <cmd>", "AI management and chat (try 'help ai')")
            table.add_row("tools <cmd>", "AI tool management (try 'help tools')")
            table.add_row("workspace switch <name>", "Switch active operation")
            table.add_row("back", "Return to main menu")
            self.rich_console.print(table)
            return

        # 2. Operation Context Help
        if current_context == "operation":
            table = Table(title="Operation Deck Commands")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row(
                "set <key> <val>", "Set operation properties (name, ticket, etc)"
            )
            table.add_row("save", "Save operation to backend")
            table.add_row("load <name>", "Load operation from backend")
            table.add_row("delete <name>", "Delete operation from backend")
            table.add_row("add <type>", "Add objects to workspace (try 'help add')")
            table.add_row("edit <path>", "Edit an existing object")
            table.add_row("delete <path>", "Delete an object from operation")
            table.add_row("vars <path>", "Inspect object variables")
            table.add_row("status", "Show operation status tree")
            table.add_row("show", "Show current operation state")
            table.add_row("use [load|unload|list]", "Manage ICE-breaker cartridges")
            table.add_row("ai <cmd>", "AI management and chat (try 'help ai')")
            table.add_row("tools <cmd>", "AI tool management (try 'help tools')")
            table.add_row("workspace switch <name>", "Switch active operation")
            table.add_row("back", "Return to main menu")
            self.rich_console.print(table)
            return

        # 3. Global Help (Root)
        if topic:
            topic = topic.lower()
            if topic == "ai":
                table = Table(title="AI Neural Link Commands")
                table.add_column("Sub-command", style="cyan")
                table.add_column("Usage", style="magenta")
                table.add_column("Description", style="white")
                table.add_row(
                    "model list", "ai model list", "List available LLM models"
                )
                table.add_row(
                    "model set", "ai model set <name>", "Change the active LLM model"
                )
                table.add_row(
                    "rag list", "ai rag list", "List available RAG knowledge bases"
                )
                table.add_row("rag use", "ai rag use <name>", "Select a RAG provider")
                table.add_row(
                    "rag off", "ai rag off", "Disable RAG (return to base LLM)"
                )
                table.add_row("rag scan", "ai rag scan", "Scan for new knowledge bases")
                table.add_row("chat", "ai chat <prompt>", "Send a message to the AI")
                table.add_row("(default)", "ai <prompt>", "Alias for 'ai chat'")
                self.rich_console.print(table)
                return
            elif topic == "tools":
                table = Table(title="Tool Commands")
                table.add_column("Sub-command", style="cyan")
                table.add_column("Usage", style="magenta")
                table.add_column("Description", style="white")
                table.add_row("list", "tools list", "List tools registered with AI")
                table.add_row(
                    "load", "tools load <func>", "Register a function as an AI tool"
                )
                self.rich_console.print(table)
                return
            elif topic == "add":
                table = Table(title="Add Commands (populate workspace)")
                table.add_column("Type", style="cyan")
                table.add_column("Usage", style="magenta")
                table.add_row("analyst", "add analyst <name> <id> <email>")
                table.add_row("device", "add device <hostname> [ip]")
                table.add_row("user", "add user <uid> <name> <email>")
                table.add_row("service", "add service <host> <port> <app>")
                table.add_row("cloudaccount", "add cloudaccount <name> <id>")
                self.rich_console.print(table)
                return
            elif topic == "show":
                table = Table(title="Show Commands")
                table.add_column("Usage", style="cyan")
                table.add_column("Description", style="white")
                table.add_row("show", "Show current context state")
                table.add_row("show options", "Show cartridge options")
                table.add_row("show commands", "Show available commands")
                table.add_row("show cartridges", "List available cartridges")
                table.add_row("show <path>", "Inspect object at path (alias for vars)")
                self.rich_console.print(table)
                return
            elif topic == "edit":
                table = Table(title="Edit Commands")
                table.add_column("Usage", style="cyan")
                table.add_column("Description", style="white")
                table.add_row("edit <path>", "Enter builder for existing object")
                table.add_row("edit device.hostname", "Edit a device by hostname")
                table.add_row(
                    "edit host.peripherals.uart0",
                    "Edit nested peripheral",
                )
                self.rich_console.print(table)
                return
            elif topic == "delete":
                table = Table(title="Delete Commands")
                table.add_column("Usage", style="cyan")
                table.add_column("Description", style="white")
                table.add_row("delete <path>", "Remove an object from the operation")
                table.add_row("delete hostname", "Delete a device")
                table.add_row(
                    "delete host.peripherals.uart0",
                    "Delete nested peripheral",
                )
                self.rich_console.print(table)
                return

        # 4. Cartridge Context Help (when a cartridge is loaded)
        if self.current_cartridge_instance:
            m_table = Table(
                title=f"ICE-breaker Commands ({self.current_cartridge_name})"
            )
            m_table.add_column("Command", style="yellow")
            m_table.add_column("Arguments", style="magenta")
            m_table.add_column("Description", style="white")
            for name, obj in inspect.getmembers(
                self.current_cartridge_instance, predicate=inspect.ismethod
            ):
                if name.startswith("do_"):
                    arg_str = self._extract_argparse_args(obj)
                    m_table.add_row(
                        name[3:], arg_str or "", obj.__doc__ or "No description"
                    )
            self.rich_console.print(m_table)

            ctx_table = Table(title="Cartridge Context Commands")
            ctx_table.add_column("Command", style="cyan")
            ctx_table.add_column("Description", style="white")
            ctx_table.add_row("set <option> <value>", "Set cartridge option")
            ctx_table.add_row("show options", "Show cartridge options")
            ctx_table.add_row("run", "Execute cartridge")
            ctx_table.add_row("status", "Show operation status tree")
            ctx_table.add_row("vars <path>", "Inspect object variables")
            ctx_table.add_row("use unload", "Unload current cartridge")
            ctx_table.add_row("back", "Unload cartridge and return")
            ctx_table.add_row("help", "Show this help")
            self.rich_console.print(ctx_table)
            return

        # 5. Global Help (Root — no cartridge, no special context)
        table = Table(title="onoSendai Command Matrix")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_row("operation [create]", "Manage operations (enter menu or create)")
        table.add_row("status", "Show visual status tree of current operation")
        table.add_row("show", "Show current context state (try 'help show')")
        table.add_row("add <type>", "Add objects to workspace (try 'help add')")
        table.add_row("edit <path>", "Edit an existing object (try 'help edit')")
        table.add_row("delete <path>", "Delete an object (try 'help delete')")
        table.add_row("vars <path>", "Inspect object variables")
        table.add_row("use [load|unload|list]", "Manage ICE-breaker cartridges")
        table.add_row("ai <cmd>", "AI management and chat (try 'help ai')")
        table.add_row("backend", "Enter backend management menu")
        table.add_row("tools <cmd>", "AI tool management (try 'help tools')")
        table.add_row("workspace switch <name>", "Switch active operation")
        table.add_row("back", "Exit current context")
        table.add_row("exit", "Disconnect from the matrix")

        self.rich_console.print(table)

    async def cmd_ai(self, *args: str) -> None:
        if not self.ai_router:
            self.rich_console.print(
                "[red][!] AI Router not initialized. Check Bedrock configuration.[/]"
            )
            return

        if not args:
            self.rich_console.print("Usage: ai <model|chat> [args]")
            return

        sub = args[0].lower()
        if sub == "model":
            if len(args) < 2:
                self.rich_console.print("Usage: ai model <set|list> [model_name]")
                return

            action = args[1].lower()
            if action == "list":
                provider = llms.get(self.ai_router.default_provider)
                table = Table(title=f"Available Models ({provider.name})")
                table.add_column("Model Name", style="cyan")
                table.add_column("Family", style="magenta")
                table.add_column("Context", style="green")
                table.add_column("Tools", style="blue")

                for m in provider.list_models():
                    table.add_row(
                        m.name,
                        m.family,
                        str(m.context_window),
                        "Yes" if m.supports_tools else "No",
                    )
                self.rich_console.print(table)
                self.rich_console.print(
                    f"Current model: [bold green]{self.ai_router.default_model}[/]"
                )

            elif action == "set" and len(args) >= 3:
                model_name = args[2]
                self.ai_router.set_default(model=model_name)
                self.rich_console.print(
                    f"[*] AI model set to: [bold green]{model_name}[/]"
                )
            else:
                self.rich_console.print("Usage: ai model set <model_name>")

        elif sub == "rag":
            if len(args) < 2:
                self.rich_console.print("Usage: ai rag <list|use|off|scan> [args]")
                return

            rag_action = args[1].lower()

            if rag_action == "list":
                table = Table(title="Available RAG Knowledge Bases")
                table.add_column("Provider Name", style="cyan")
                table.add_column("Type", style="magenta")
                table.add_column("Description", style="white")

                found_any = False
                for name in llms.providers():
                    if name.startswith("rag-"):
                        provider = llms.get(name)
                        # Try to get more info if available, otherwise generic
                        desc = "RAG Integration"
                        # Check for RAGProvider specific attributes safely
                        if hasattr(provider, "persist_dir"):
                            desc = f"Local KB: {getattr(provider, 'persist_dir', 'Unknown')}"
                        elif hasattr(provider, "config"):
                            # Fallback for Bedrock/other providers if they have config
                            desc = f"KB: {getattr(getattr(provider, 'config', None), 'knowledge_base_id', 'N/A')}"

                        table.add_row(
                            name,
                            "AWS Bedrock RAG" if "bedrock" in name else "RAG",
                            desc,
                        )
                        found_any = True

                if not found_any:
                    self.rich_console.print("[yellow]No RAG providers found.[/]")
                else:
                    self.rich_console.print(table)

            elif rag_action == "use":
                if len(args) < 3:
                    self.rich_console.print("Usage: ai rag use <name>")
                    return
                rag_name = args[2]
                if rag_name in llms.providers():
                    self.ai_router.set_default(provider=rag_name)
                    self.rich_console.print(f"[bold green]✔[/] RAG engaged: {rag_name}")
                else:
                    self.rich_console.print(
                        f"[red][!] Unknown RAG provider: {rag_name}[/]"
                    )

            elif rag_action == "off":
                # Reset to a default non-RAG provider.
                # Ideally we'd know what the 'base' one was, but 'bedrock' is a safe bet for this environment.
                # Or we check if 'bedrock' exists, else 'openai', else first available.
                base = "bedrock"
                if base not in llms.providers():
                    # Fallback to first non-rag
                    for p in llms.providers():
                        if not p.startswith("rag-"):
                            base = p
                            break

                self.ai_router.set_default(provider=base)
                self.rich_console.print(
                    f"[bold green]✔[/] RAG disengaged. Switched to: {base}"
                )

            elif rag_action == "scan":
                self.rich_console.print("[*] Scanning for new knowledge bases...")
                new_rags = bootstrap_rags(llms)
                if new_rags:
                    self.rich_console.print(
                        f"[bold green]✔[/] Found and registered {len(new_rags)} RAGs:"
                    )
                    for r in new_rags:
                        self.rich_console.print(f"  - {r.name}")
                else:
                    self.rich_console.print("[*] No new RAG configurations found.")

            else:
                self.rich_console.print(f"Unknown RAG command: {rag_action}")

        elif sub == "chat" or (sub not in ["model", "rag"]):
            # Default to chat if not 'model' or 'rag'
            prompt = " ".join(args[1:]) if sub == "chat" else " ".join(args)
            if not prompt:
                self.rich_console.print("Usage: ai chat <prompt>")
                return

            with Status("[bold blue]AI is thinking...", spinner="dots"):
                from wintermute.ai.types import Message, ToolSpec

                # Fetch all registered tools for the context
                raw_tools = await self.tools_runtime.get_all_tools()
                tool_specs = [
                    ToolSpec(
                        name=t["function"]["name"],
                        description=t["function"]["description"],
                        input_schema=t["function"]["parameters"],
                        output_schema={},  # Simplified
                    )
                    for t in raw_tools
                ]

                messages = [Message(role="user", content=prompt)]

                # Use tool_calling_chat instead of simple_chat to handle complex responses
                resp = tool_calling_chat(
                    self.ai_router,
                    messages,
                    tools=tool_specs,
                    model=self.ai_router.default_model,
                )

            # Display content if present
            if resp.content:
                self.rich_console.print(
                    Panel(resp.content, title="Wintermute AI", border_style="blue")
                )

            # Display tool calls if present
            if resp.tool_calls:
                t_table = Table(title="AI Tool Calls Requested")
                t_table.add_column("ID", style="cyan")
                t_table.add_column("Tool", style="magenta")
                t_table.add_column("Arguments", style="white")
                for tc in resp.tool_calls:
                    t_table.add_row(tc.id, tc.name, str(tc.arguments))
                self.rich_console.print(t_table)

                # Optional: Logic to actually execute them and loop back could go here
                # For now, we just show them as requested by user.

    async def cmd_backend_enter(self) -> None:
        """Push backend context."""
        if self.context_stack[-1] != "backend":
            self.context_stack.append("backend")

    async def cmd_backend_list(self) -> None:
        """List active backends."""
        table = Table(title="📡 Active Cyber-Backends", border_style="bright_blue")
        table.add_column("Interface", style="cyan")
        table.add_column("Endpoint/Path", style="magenta")
        table.add_column("Status", style="green")

        # Storage backends
        if Operation._backend:
            table.add_row("Data Persistence", str(Operation._backend), "ACTIVE")

        # Ticket backends
        if Ticket._backend:
            table.add_row("Incident Tracking", str(Ticket._backend), "ACTIVE")

        # Report backends
        if Report._backend:
            table.add_row("Intelligence Reporting", str(Report._backend), "ACTIVE")

        self.rich_console.print(table)

    async def cmd_backend_available(self) -> None:
        """List supported backend types."""
        catalog = self._scan_backends()

        table = Table(
            title="🛠 Supported Neural Interfaces", border_style="bright_magenta"
        )
        table.add_column("Category", style="cyan", justify="right")
        table.add_column("Name", style="yellow")
        table.add_column("Description", style="white")

        # Group by category
        categories: Dict[str, List[tuple[str, str]]] = {}
        for name, meta in catalog.items():
            cat = meta["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((name, meta["description"]))

        # Sort categories for consistent UI
        for cat in sorted(categories.keys()):
            for name, desc in sorted(categories[cat]):
                table.add_row(cat, name, desc)

        self.rich_console.print(table)
        self.rich_console.print(
            "[dim]Use 'setup <name>' to initialize an interface.[/]"
        )

    def _get_backend_params(self, backend_name: str) -> list[tuple[str, str]]:
        """Get constructor parameter names and types for a backend class.

        Args:
            backend_name: The name of the backend module (e.g., 'bugzilla')

        Returns:
            A list of (param_name, param_type) tuples for the __init__ method.
        """
        try:
            # Import the backend module
            mod = importlib.import_module(f"wintermute.backends.{backend_name}")

            # Find the backend class (typically named after the module)
            backend_class = None
            for name, obj in inspect.getmembers(mod):
                if inspect.isclass(obj) and name.lower() == backend_name.lower():
                    backend_class = obj
                    break

            if backend_class is None:
                return []

            # Get the __init__ signature
            sig = inspect.signature(backend_class.__init__)
            params: list[tuple[str, str]] = []

            for name, param in sig.parameters.items():
                if name in ["self", "args", "kwargs"]:
                    continue
                # Get type annotation if available
                if param.annotation != inspect.Parameter.empty:
                    param_type = str(param.annotation)
                else:
                    param_type = "Any"
                params.append((name, param_type))

            return params
        except Exception:
            return []

    async def cmd_backend_setup(self, *args: str) -> None:
        """Setup a specific backend using dynamic parameter discovery."""
        if len(args) < 1:
            self.rich_console.print("Usage: setup <type>")
            return

        itype = args[0].lower()

        # Get backend parameters dynamically
        params = self._get_backend_params(itype)

        if not params:
            self.rich_console.print(
                f"[yellow][!] No parameter info available for '{itype}'. Using defaults.[/]"
            )

        # Build kwargs from user input
        kwargs: dict[str, Any] = {}
        for param_name, param_type in params:
            # Create prompt based on parameter name
            prompt_text = f"{param_name}: "
            is_password = (
                "password" in param_name.lower() or "key" in param_name.lower()
            )

            value = await self.session.prompt_async(
                prompt_text, is_password=is_password
            )
            if value:
                # Try to infer type for common cases
                if "path" in param_name.lower() or "dir" in param_name.lower():
                    # Keep as string (path)
                    kwargs[param_name] = value or None
                elif param_type == "int" or "int" in param_type:
                    try:
                        kwargs[param_name] = int(value)
                    except ValueError:
                        kwargs[param_name] = value
                elif param_type == "bool" or "bool" in param_type:
                    kwargs[param_name] = value.lower() in ["true", "yes", "1"]
                else:
                    kwargs[param_name] = value

        try:
            # Import the backend module
            mod = importlib.import_module(f"wintermute.backends.{itype}")

            # Find the backend class
            backend_class = None
            for name, obj in inspect.getmembers(mod):
                if inspect.isclass(obj) and name.lower() == itype.lower():
                    backend_class = obj
                    break

            if backend_class is None:
                self.rich_console.print(
                    f"[red][!] Could not find backend class for '{itype}'[/]"
                )
                return

            # Instantiate backend with collected parameters
            backend = backend_class(**kwargs)

            # Register based on backend category
            backend_category = getattr(mod, "__category__", "Miscellaneous").lower()

            if "ticket" in backend_category or "bugzilla" in itype:
                Ticket.register_backend(itype, backend, make_default=True)
                self.rich_console.print(
                    f"[bold green]✔[/] Ticket backend established: {itype}"
                )
            elif "report" in backend_category or "docx" in itype:
                Report.register_backend(itype, backend, make_default=True)
                self.rich_console.print(
                    f"[bold green]✔[/] Reporting backend established: {itype}"
                )
            else:
                Operation.register_backend(itype, backend, make_default=True)
                self.rich_console.print(
                    f"[bold green]✔[/] Backend established: {itype}"
                )

        except Exception as e:
            self.rich_console.print(f"[red][!] Backend setup error: {e}[/]")

    def cmd_tools(self, *args: str) -> None:
        if not args:
            self.rich_console.print("Usage: tools <load|list> [args]")
            return

        sub = args[0].lower()
        if sub == "list":
            table = Table(title="Loaded AI Tools")
            table.add_column("Tool Name", style="cyan")
            table.add_column("Description", style="white")

            # Correctly access loaded tools from the global registry
            for name, tool in global_tool_registry._tools.items():
                table.add_row(
                    name,
                    tool.description[:100] + "..."
                    if len(tool.description) > 100
                    else tool.description,
                )

            self.rich_console.print(table)

        elif sub == "load" and len(args) >= 2:
            func_name = args[1]
            try:
                # Try to find the function in common modules
                # This is a bit tricky, ideally we'd have a list of safe modules
                # For now, let's try to import it if it's a full path, or look in core/findings
                import wintermute.core
                import wintermute.findings

                func = None
                if "." in func_name:
                    mod_name, f_name = func_name.rsplit(".", 1)
                    mod = importlib.import_module(mod_name)
                    func = getattr(mod, f_name)
                else:
                    for mod in [wintermute.core, wintermute.findings]:
                        if hasattr(mod, func_name):
                            func = getattr(mod, func_name)
                            break

                if func and callable(func):
                    tools = register_tools([func])
                    for t in tools:
                        global_tool_registry.register(t)
                    self.rich_console.print(
                        f"[*] Successfully loaded tool: [bold green]{func_name}[/]"
                    )
                else:
                    self.rich_console.print(
                        f"[red][!] Could not find callable function: {func_name}[/]"
                    )
            except Exception as e:
                self.rich_console.print(f"[red][!] Error loading tool: {e}[/]")

    # --- Main Loop ---

    async def _dispatch_main_commands(self, cmd: str, args: List[str]) -> bool:
        """Handlers for Main Menu / Global functional commands."""
        if cmd == "operation":
            if args and args[0] == "create":
                self.cmd_operation_create(args[1] if len(args) > 1 else "default")
            else:
                self.cmd_operation_enter()
            return True

        elif cmd == "add":
            if not args:
                self.rich_console.print("Usage: add <entity_type>")
                return True
            entity = args[0].lower()
            # Always use the interactive builder for 'add' now
            self.cmd_add_enter(entity)
            return True

        elif cmd == "edit" and len(args) >= 1:
            self.cmd_edit(" ".join(args))
            return True

        elif cmd == "delete" and len(args) >= 1:
            self.cmd_delete(" ".join(args))
            return True

        elif cmd == "use":
            self.cmd_use(*args)
            return True

        elif cmd == "set" and len(args) >= 2 and not self.builder_stack:
            # Cartridge option setting (if not in builder)
            self.cmd_set(args[0], args[1])
            return True

        elif cmd == "run":
            self.cmd_run()
            return True

        elif cmd == "show":
            if args and args[0] == "options":
                self.show_options()
            elif args and args[0] == "commands":
                self.show_commands()
            elif args and args[0] == "cartridges":
                self.rich_console.print(
                    f"Available Cartridges: {', '.join(self.available_cartridges)}"
                )
            elif args:
                # show <path> — alias for vars
                self.cmd_vars(" ".join(args))
            else:
                # Bare 'show' — contextual
                if self.current_cartridge_name:
                    self.show_options()
                elif self.context_stack[-1] == "operation":
                    self.cmd_show_current_context()
                else:
                    self.cmd_status()
            return True

        elif cmd == "vars" and args:
            self.cmd_vars(" ".join(args))
            return True

        elif cmd == "ai" and args:
            await self.cmd_ai(*args)
            return True

        elif cmd == "backend":
            await self.cmd_backend_enter()
            return True

        elif cmd == "tools" and args:
            self.cmd_tools(*args)
            return True

        # Dynamic Cartridge Commands (only if loaded)
        elif self.current_cartridge_instance and hasattr(
            self.current_cartridge_instance, f"do_{cmd}"
        ):
            method = getattr(self.current_cartridge_instance, f"do_{cmd}")
            try:
                # Check if method is async
                if inspect.iscoroutinefunction(method):
                    await method(*args)
                else:
                    method(*args)
            except Exception as e:
                self.rich_console.print(f"[red][!] Cartridge command error: {e}[/]")
            return True

        return False

    async def run(self) -> None:
        self.display_banner()

        while True:
            completer = self.update_completer()
            try:
                with patch_stdout():
                    user_input = await self.session.prompt_async(
                        self, completer=completer, style=self.style
                    )

                if not user_input.strip():
                    continue

                parts = user_input.split()
                cmd = parts[0].lower()
                args = parts[1:]

                # 1. Primary Global Navigation
                if cmd == "exit":
                    break
                elif cmd == "back":
                    self.cmd_back()
                    continue
                elif cmd == "help":
                    self.show_commands(args[0] if args else None)
                    continue
                elif cmd == "status":
                    self.cmd_status()
                    continue
                elif cmd == "workspace":
                    # Global dispatch for workspace
                    if args and args[0] == "switch":
                        self.cmd_workspace_switch(
                            args[1] if len(args) > 1 else "default"
                        )
                    else:
                        self.rich_console.print("Usage: workspace switch <name>")
                    continue

                # 2. Context-Specific Dispatch
                current_context = self.context_stack[-1]
                handled = False

                if self.builder_stack:
                    # --- BUILDER CONTEXT HANDLER ---
                    handled = True
                    if cmd == "set" and len(args) >= 2:
                        self.cmd_builder_set(args[0], " ".join(args[1:]))
                    elif cmd == "show":
                        self.cmd_builder_show()
                    elif cmd == "save" or cmd == "create":
                        self.cmd_builder_save()
                    elif cmd == "add" and args:
                        # NEW STRICT ROUTING
                        # Check for 'add peripheral <type>'
                        if args[0] == "peripheral" and len(args) > 1:
                            p_type = args[1].lower()
                            if p_type in self.PERIPHERAL_MAP:
                                self.builder_stack.append(
                                    BuilderContext(
                                        p_type,
                                        self.PERIPHERAL_MAP[p_type],
                                        parent_list_name="peripherals",
                                    )
                                )
                                self.rich_console.print(
                                    f"[*] Constructing {p_type} node..."
                                )
                            else:
                                self.rich_console.print(
                                    f"[red][!] Unknown peripheral type: {p_type}[/]"
                                )

                        # Check for 'add vulnerability'
                        elif args[0] == "vulnerability":
                            from wintermute.findings import Vulnerability

                            self.builder_stack.append(
                                BuilderContext(
                                    "vulnerability",
                                    Vulnerability,
                                    parent_list_name="vulnerabilities",
                                )
                            )
                            self.rich_console.print(
                                "[*] Constructing vulnerability node..."
                            )

                        # Check for cloud nested types (AWS only)
                        elif (
                            args[0].lower() in self.CLOUD_NESTED_MAP
                            and self._is_cloud_builder_aws()
                        ):
                            cloud_cls, parent_list = self.CLOUD_NESTED_MAP[
                                args[0].lower()
                            ]
                            self.builder_stack.append(
                                BuilderContext(
                                    args[0].lower(),
                                    cloud_cls,
                                    parent_list_name=parent_list,
                                )
                            )
                            self.rich_console.print(
                                f"[*] Constructing {args[0].lower()} node..."
                            )

                        else:
                            # Generic fallback for other nested items (e.g. service inside device)
                            self.cmd_add_enter(args[0])
                    else:
                        handled = False  # Try global handler

                if not handled:
                    if current_context == "backend":
                        # --- BACKEND CONTEXT COMMANDS ---
                        handled = True
                        if cmd == "list":
                            await self.cmd_backend_list()
                        elif cmd == "available":
                            await self.cmd_backend_available()
                        elif cmd == "setup":
                            await self.cmd_backend_setup(*args)
                        else:
                            handled = False

                    elif current_context == "operation":
                        # --- OPERATION CONTEXT COMMANDS ---
                        handled = True
                        if cmd == "set" and len(args) >= 2:
                            self.cmd_operation_set(args[0], args[1])
                        elif cmd == "save":
                            self.cmd_operation_save()
                        elif cmd == "load" and args:
                            self.cmd_operation_load(args[0])
                        elif cmd == "delete" and args:
                            self.cmd_operation_delete(args[0])
                        else:
                            handled = False

                # 3. Global Functional Fallback
                if not handled:
                    handled = await self._dispatch_main_commands(cmd, args)

                if not handled and cmd:
                    self.rich_console.print(
                        f"[red][!] ICE rejected: unknown command '{cmd}'[/]"
                    )

            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            except Exception as e:
                self.rich_console.print(f"[red][!] Console Error: {e}[/]")
                logger.exception("REPL Error")

        self.rich_console.print(
            "[bold red]Flatline. Disconnecting from the matrix...[/]"
        )


def main() -> None:
    console = WintermuteConsole()
    asyncio.run(console.run())


if __name__ == "__main__":
    main()
