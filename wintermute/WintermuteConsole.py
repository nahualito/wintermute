# -*- coding: utf-8 -*-
"""
Wintermute REPL Console
-----------------------
A Metasploit-style REPL using prompt-toolkit and rich.
"""

import asyncio
import importlib
import inspect
import json
import logging
import os
import re
import shlex
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Type

from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.table import Table
from rich.tree import Tree

from wintermute.ai.agent import (
    DEFAULT_IMPLEMENTATIONS_DIR,
    WorkerAgent,
    init_agent_environment,
)
from wintermute.ai.bootstrap import bootstrap_rags, init_router
from wintermute.ai.jobs import AgentJobManager
from wintermute.ai.provider import Router, llms
from wintermute.ai.tools_runtime import ToolsRuntime
from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.types import ChatRequest, Message, ToolSpec
from wintermute.ai.utils.tool_factory import register_tools
from wintermute.backends.json_storage import JsonFileBackend
from wintermute.basemodels import CloudAccount
from wintermute.cloud.aws import AWSService, AWSUser, IAMRole, IAMUser
from wintermute.core import (
    Analyst,
    AWSAccount,
    Device,
    Operation,
    RunStatus,
    Service,
    TestCase,
    TestCaseRun,
    TestPlan,
    User,
)
from wintermute.findings import Vulnerability
from wintermute.hardware import Architecture, Memory, Processor
from wintermute.integrations.mcp_runtime import MCPClientManager
from wintermute.peripherals import (
    JTAG,
    TPM,
    UART,
    USB,
    Bluetooth,
    Ethernet,
    PCIe,
    RenodeEmulator,
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
        target_collection: Optional[List[Any]] = None,
    ) -> None:
        self.entity_name = entity_name
        self.entity_class = entity_class
        self.parent_list_name = parent_list_name
        # Live list reference resolved from a schema-driven nested route
        # (e.g. ``device.peripherals``). When set, ``cmd_builder_save``
        # appends the constructed object straight to this list instead of
        # routing through one of the operation-level convenience methods.
        self.target_collection: Optional[List[Any]] = target_collection
        self.properties: Dict[str, Any] = {}
        # Store original object reference for edit mode
        self._original_object: Any | None = None


class WintermuteConsole:
    def __init__(self) -> None:
        self.rich_console = Console()
        self.session: PromptSession[Any] = PromptSession(history=InMemoryHistory())
        self.operation = Operation(operation_name="default")
        self.tools_runtime = ToolsRuntime()
        # UX state: tracks the active sub-menu (mcp/tools/operation/add). The
        # prompt renderer in `run()` reads this string verbatim, so anything
        # truthy will surface as `[<context>]` in the prompt. Reset by `back`.
        self.current_context: str = ""
        # Outbound MCP client manager — owns ~/.wintermute/mcp_servers.json and a
        # background asyncio loop on a daemon thread. Instantiation is cheap;
        # the loop only spins up when the operator first runs `mcp start`.
        self.mcp_manager = MCPClientManager()

        # Background job manager for spawned WorkerAgents. Supervisor REPL
        # uses this exclusively (via the `spawn_agent` tool); operator can
        # poll via `ai agent status [job_id]`.
        self.job_manager: AgentJobManager = AgentJobManager()

        # First-run seeding: copy the bundled default agent profiles from
        # the wintermute.data.agent_profiles package into the user's
        # ~/.wintermute/agentic/profiles/ directory. Idempotent — never
        # overwrites local edits.
        try:
            init_agent_environment()
        except Exception as exc:  # noqa: BLE001 — never block startup
            logger.warning("init_agent_environment failed: %s", exc)

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
            "renodeemulator": RenodeEmulator,
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
            "renodeemulator": RenodeEmulator,
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

        # Local AI tools — bound to *this* console's active_operation so the
        # `ai chat` flow can list / inspect / mutate test runs without going
        # through the MCP ObjectRegistry. Registered into the global tool
        # registry so `tool_calling_chat` picks them up on the next request.
        for _ai_tool in register_tools(
            [
                self.ai_list_test_runs,
                self.ai_get_run_details,
                self.ai_update_run_status,
                self.ai_add_run_note,
            ]
        ):
            global_tool_registry.register(_ai_tool)

    @property
    def active_operation(self) -> Operation:
        """Live alias for the operation currently held in ``self.operation``.

        Stays in sync even when the operation is reassigned (e.g. via
        ``operation create`` / ``workspace switch``), so callers can rely on
        a single attribute name regardless of how the operation was loaded.
        """
        return self.operation

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
        """Render the active builder as a schema-aware Property/Type/Value
        table.

        The previous implementation only iterated ``builder.properties``,
        leaving the operator with no idea what fields the entity even
        accepted until they guessed a name and watched ``set`` succeed.

        We now introspect ``cls.__init__`` (the closest thing the
        homegrown ``wintermute.basemodels.BaseModel`` has to a Pydantic
        ``model_fields``) to enumerate every constructor parameter, with
        its type annotation. Unset parameters render as ``<unset>`` so
        the user knows exactly what's available without fishing in
        source files.
        """
        if not self.builder_stack:
            self.rich_console.print("[red]No active builder.[/]")
            return

        active_builder = self.builder_stack[-1]
        target = active_builder.entity_name
        cls = active_builder.entity_class

        table = Table(title=f"Building: {target}", border_style="bright_blue")
        table.add_column("Property", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Value", style="green")

        # ----- Discover the schema -------------------------------------
        # Constructor parameters in declaration order are the source of
        # truth for "what fields does this entity accept?". Anything
        # already in `properties` but missing from the signature is
        # appended afterwards so dynamically-added fields stay visible.
        ordered, types = self._introspect_constructor_fields(cls)
        for k in active_builder.properties:
            if k not in ordered:
                ordered.append(k)

        if not ordered:
            table.add_row("[dim]<no fields available>[/]", "", "")
            self.rich_console.print(table)
            return

        for field_name in ordered:
            type_label = types.get(field_name, "")
            if field_name in active_builder.properties:
                value_str = self._format_property_value(
                    active_builder.properties[field_name]
                )
            else:
                value_str = "[dim]<unset>[/]"
            table.add_row(field_name, type_label, value_str)

        self.rich_console.print(table)

    @classmethod
    def _introspect_constructor_fields(
        cls, target_cls: Optional[type]
    ) -> tuple[List[str], Dict[str, str]]:
        """Return ``(ordered_field_names, type_labels)`` for ``target_cls``.

        Walks ``target_cls.__init__``'s signature (the closest thing the
        homegrown ``wintermute.basemodels.BaseModel`` has to a Pydantic
        ``model_fields``). Returns empty containers if introspection
        fails or ``target_cls`` is None — callers decide how to handle
        the empty case.
        """
        ordered: List[str] = []
        types: Dict[str, str] = {}
        if target_cls is None:
            return ordered, types
        try:
            sig = inspect.signature(target_cls)
        except (TypeError, ValueError):
            return ordered, types
        for name, param in sig.parameters.items():
            if name in ("self", "args", "kwargs"):
                continue
            if param.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            ordered.append(name)
            types[name] = cls._format_field_type(param.annotation)
        return ordered, types

    @staticmethod
    def _format_field_type(annotation: Any) -> str:
        """Stringify a constructor parameter annotation for the show table."""
        if annotation is inspect.Parameter.empty:
            return "any"
        if hasattr(annotation, "__name__"):
            return str(annotation.__name__)  # plain types: str, int, bool, …
        s = str(annotation).replace("typing.", "").replace("NoneType", "None")
        if len(s) > 60:
            s = s[:57] + "…"
        return s

    @staticmethod
    def _format_property_value(value: Any) -> str:
        """Render a *set* property value for the show table."""
        if isinstance(value, list):
            if not value:
                return "[]"
            items = []
            for item in value:
                if hasattr(item, "name"):
                    items.append(f"- {item.name}")
                elif hasattr(item, "hostname"):
                    items.append(f"- {item.hostname}")
                elif hasattr(item, "title"):
                    items.append(f"- {item.title}")
                elif hasattr(item, "uid"):
                    items.append(f"- {item.uid}")
                else:
                    items.append(f"- {item!r}")
            return "\n".join(items)
        return str(value)

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

                # Schema-driven nested append: when the builder was opened
                # with a ``target_collection`` (e.g. via
                # ``peripherals add ...`` inside ``[devices/rasp1]``) the
                # resolved live list is the source of truth. Append there
                # and bypass the operation-level convenience routing
                # entirely so we can support any class registered in a
                # parent's ``__schema__``.
                if active_builder.target_collection is not None:
                    active_builder.target_collection.append(entity_obj)
                    ident = self._object_identity(entity_obj)
                    self.rich_console.print(
                        f"[bold green]✔[/] Saved {type(entity_obj).__name__} "
                        f"[bold]{ident}[/] to nested collection."
                    )
                    self.cmd_back()
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
        target_collection: Optional[List[Any]] = None,
    ) -> None:
        """Enter a builder context for a specific entity.

        ``target_collection`` is the *live list reference* the constructed
        object should be appended to on save. The schema-driven nested
        editor sets this when a `<cmd> add` is dispatched against a live
        object's ``__schema__`` field; legacy operation-root paths leave
        it ``None`` so :meth:`cmd_builder_save` keeps using the existing
        ``addAnalyst`` / ``addDevice`` / ``addUser`` conveniences.
        """
        if not cls:
            cls = self.ENTITY_CLASSES.get(entity_type)

        ctx = BuilderContext(
            entity_type,
            entity_class=cls,
            parent_list_name=parent_list,
            target_collection=target_collection,
        )
        self.builder_stack.append(ctx)
        self.rich_console.print(f"[*] Constructing {entity_type} node...")

    def cmd_back(self) -> None:
        """Pops the current context from the stack and clears the UI menu."""
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

        # The new UI menu marker pops one level at a time so deep contexts
        # like `cartridges/tpm20` step through `cartridges` → root cleanly:
        #   * `cartridges/<name>`         → `cartridges`
        #   * `testruns/<run_id>`         → `testruns`
        #   * `<domain>/.../<key>/<id>`   → `<domain>/...` (one pair off
        #                                    the tail; supports arbitrary
        #                                    schema-driven depth)
        #   * `<domain>/<id>`             → `<domain>`
        #   * anything else               → root (`""`)
        if self.current_context.startswith("cartridges/"):
            self.current_context = "cartridges"
        elif self.current_context.startswith("testruns/"):
            self.current_context = "testruns"
        elif "/" in self.current_context:
            parts = self.current_context.split("/")
            domain = parts[0]
            if domain not in self._DOMAIN_SPECS:
                self.current_context = ""
            elif len(parts) <= 2:
                # `devices/rasp1` → `devices`.
                self.current_context = domain
            else:
                # Schema-driven deep path: drop the last
                # `<schema_key>/<id>` pair so each `back` walks one
                # level toward the root (e.g.
                # ``devices/rasp1/services/80`` → ``devices/rasp1``).
                self.current_context = "/".join(parts[:-2])
        else:
            self.current_context = ""

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

        elif sub == "agent":
            await self._cmd_ai_agent(list(args[1:]))

        elif sub == "chat" or (sub not in ["model", "rag", "agent"]):
            # The supervisor REPL. The REPL itself is the high-level
            # Orchestrator: it speaks only to the LLM with its three
            # exclusive native tools (generate_implementation_file,
            # spawn_agent, check_agent_status). Worker tools live with
            # WorkerAgents spawned via the job manager — the supervisor
            # never sees the global cartridge tool surface, by design.
            prompt = " ".join(args[1:]) if sub == "chat" else " ".join(args)
            if not prompt:
                self.rich_console.print("Usage: ai chat <prompt>")
                return

            with Status("[bold blue]Supervisor thinking...", spinner="dots"):
                final = await self._run_supervisor(prompt)

            if final:
                self.rich_console.print(
                    Panel(final, title="Wintermute Supervisor", border_style="blue")
                )

    # -----------------------------------------------------------------
    # Supervisor REPL — Phase 4 Orchestrator
    # -----------------------------------------------------------------

    SUPERVISOR_SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Wintermute Supervisor — the high-level orchestrator of a "
        "multi-agent hardware-security framework. You do NOT execute hardware "
        "tools yourself. Instead, you delegate to specialist WorkerAgents.\n\n"
        "Your only three tools are:\n"
        "  1. generate_implementation_file(content, filename) — write a "
        "step-by-step plan to ~/.wintermute/agentic/implementations/<filename>.\n"
        "  2. spawn_agent(profile, implementation_file, mode) — instantiate a "
        "WorkerAgent from a profile (~/.wintermute/agentic/profiles/<profile>.md), "
        "load the implementation, and schedule it via the AgentJobManager. "
        "`mode` is 'background' (default) or 'foreground'.\n"
        "  3. check_agent_status(job_id) — poll a previously spawned job.\n\n"
        "If the operator asks a simple factual question that requires no "
        "delegation, just answer directly. Only use the tools when the task "
        "requires running specialist work."
    )

    SUPERVISOR_TOOL_SPECS: ClassVar[List[Dict[str, Any]]] = [
        {
            "name": "generate_implementation_file",
            "description": (
                "Write a step-by-step execution plan to "
                "~/.wintermute/agentic/implementations/<filename>. Returns the "
                "absolute path of the file written."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Markdown body of the implementation plan.",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Filename (e.g. 'tpm_quote_verify.md').",
                    },
                },
                "required": ["content", "filename"],
            },
        },
        {
            "name": "spawn_agent",
            "description": (
                "Spawn a WorkerAgent from a markdown profile and queue it on "
                "the AgentJobManager. Returns either a job_id (background) or "
                "the agent's final output (foreground)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": (
                            "Profile name (without .md), looked up in "
                            "~/.wintermute/agentic/profiles/."
                        ),
                    },
                    "implementation_file": {
                        "type": "string",
                        "description": (
                            "Filename relative to "
                            "~/.wintermute/agentic/implementations/."
                        ),
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["background", "foreground"],
                        "description": "'background' (default) returns a job_id immediately.",
                    },
                },
                "required": ["profile", "implementation_file"],
            },
        },
        {
            "name": "check_agent_status",
            "description": "Poll a previously spawned agent by job_id.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "Job id returned by spawn_agent.",
                    },
                },
                "required": ["job_id"],
            },
        },
    ]

    SUPERVISOR_MAX_ITERATIONS: ClassVar[int] = 12

    def _supervisor_tool_specs(self) -> List[ToolSpec]:
        return [
            ToolSpec(
                name=t["name"],
                description=t["description"],
                input_schema=t["input_schema"],
                output_schema={},
            )
            for t in self.SUPERVISOR_TOOL_SPECS
        ]

    async def _supervisor_dispatch(self, name: str, args: Dict[str, Any]) -> str:
        """Execute one Supervisor-native tool call. Always returns a string
        suitable for the ``role='tool'`` message that feeds back into the
        next LLM turn.
        """
        if name == "generate_implementation_file":
            content = str(args.get("content", ""))
            filename = str(args.get("filename", "")).strip()
            if not filename:
                return json.dumps({"error": "filename is required"})
            target = DEFAULT_IMPLEMENTATIONS_DIR / filename
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            except OSError as exc:
                return json.dumps({"error": f"write failed: {exc}"})
            return json.dumps({"path": str(target), "bytes": len(content)})

        if name == "spawn_agent":
            if self.ai_router is None:
                return json.dumps({"error": "AI router not initialised"})
            profile = str(args.get("profile", "")).strip()
            impl_file = str(args.get("implementation_file", "")).strip()
            mode = str(args.get("mode", "background")).strip().lower() or "background"
            if not profile or not impl_file:
                return json.dumps(
                    {"error": "profile and implementation_file are required"}
                )
            try:
                agent = WorkerAgent(router=self.ai_router)
                agent.load_profile(profile)
                agent.load_implementation(impl_file)
            except FileNotFoundError as exc:
                return json.dumps({"error": str(exc)})
            # Plumb global-registry tools into the agent's isolated
            # registry — only the ones the profile allow-lists.
            for tname in agent.allowed_tools:
                tool = global_tool_registry._tools.get(tname)
                if tool is not None:
                    agent.register_tool(tool)
            if mode == "foreground":
                try:
                    output = await agent.run()
                except Exception as exc:  # noqa: BLE001 — surface to LLM
                    return json.dumps({"error": f"agent raised: {exc}"})
                return json.dumps({"mode": "foreground", "output": output})
            job_id = await self.job_manager.spawn_job(agent)
            return json.dumps(
                {"mode": "background", "job_id": job_id, "agent_name": agent.name}
            )

        if name == "check_agent_status":
            job_id = str(args.get("job_id", "")).strip()
            if not job_id:
                return json.dumps({"error": "job_id is required"})
            snap = await self.job_manager.get_status(job_id)
            if snap is None:
                return json.dumps({"error": f"unknown job_id {job_id!r}"})
            return json.dumps(snap, default=str)

        return json.dumps({"error": f"unknown supervisor tool {name!r}"})

    async def _run_supervisor(self, prompt: str) -> str:
        """Run the bounded supervisor tool-calling loop.

        Mirrors :meth:`WorkerAgent.run` (same frozen-Message bypass and
        same arguments-string/parsed-dict split for LiteLLM history vs.
        local execution), but the toolset is locked to the three
        supervisor-native tools defined above.
        """
        if self.ai_router is None:
            return "[!] AI router not initialised."

        messages: List[Message] = [
            Message(role="system", content=self.SUPERVISOR_SYSTEM_PROMPT),
            Message(role="user", content=prompt),
        ]
        tool_specs = self._supervisor_tool_specs()

        iteration = 0
        while True:
            if iteration >= self.SUPERVISOR_MAX_ITERATIONS:
                return (
                    "[Supervisor] Iteration cap reached "
                    f"({self.SUPERVISOR_MAX_ITERATIONS}) without finishing."
                )
            iteration += 1

            req = ChatRequest(
                messages=messages,
                tools=tool_specs,
                model=self.ai_router.default_model,
                tool_choice="auto",
            )
            provider, chosen = self.ai_router.choose(req)
            resp = provider.chat(chosen)

            if not resp.tool_calls:
                return resp.content or ""

            formatted_tool_calls = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": tc.arguments
                        if isinstance(tc.arguments, str)
                        else json.dumps(tc.arguments),
                    },
                }
                for tc in resp.tool_calls
            ]
            assistant_msg = Message(role="assistant", content=resp.content or "")
            # Dataclass bypass per AGENT_REFACTOR_PLAN architectural rules.
            object.__setattr__(assistant_msg, "tool_calls", formatted_tool_calls)
            messages.append(assistant_msg)

            for tc in resp.tool_calls:
                if isinstance(tc.arguments, str):
                    try:
                        parsed: Dict[str, Any] = (
                            json.loads(tc.arguments) if tc.arguments else {}
                        )
                    except json.JSONDecodeError:
                        parsed = {}
                else:
                    parsed = dict(tc.arguments)
                tool_output = await self._supervisor_dispatch(tc.name, parsed)
                messages.append(
                    Message(
                        role="tool",
                        content=tool_output,
                        tool_name=tc.name,
                        tool_call_id=tc.id,
                    )
                )

    async def _cmd_ai_agent(self, args: List[str]) -> None:
        """Operator-facing inspection of the background job manager.

        Supports ``ai agent status`` (list all jobs) and
        ``ai agent status <job_id>`` (single-job snapshot).
        """
        if not args or args[0] != "status":
            self.rich_console.print("Usage: ai agent status [job_id]")
            return
        if len(args) >= 2:
            job_id = args[1]
            snap = await self.job_manager.get_status(job_id)
            if snap is None:
                self.rich_console.print(f"[red][!] Unknown job_id: {job_id}[/]")
                return
            t = Table(title=f"Agent Job {job_id}")
            t.add_column("Field", style="cyan")
            t.add_column("Value", style="white")
            for k, v in snap.items():
                t.add_row(k, str(v))
            self.rich_console.print(t)
            return
        jobs = await self.job_manager.list_jobs()
        if not jobs:
            self.rich_console.print("[*] No agent jobs have been spawned this session.")
            return
        t = Table(title="Agent Jobs")
        t.add_column("job_id", style="cyan")
        t.add_column("agent", style="magenta")
        t.add_column("status", style="green")
        for j in jobs:
            t.add_row(j["job_id"], j.get("agent_name", ""), j["status"])
        self.rich_console.print(t)

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

    # --- Help / Show / Add (UX overhaul) -----------------------------------

    def cmd_help(self, args: List[str]) -> None:
        """Context-aware help.

        Resolution order:
            1. Explicit topic (``help mcp``).
            2. Active sub-menu (``self.current_context``).
            3. Main menu fallback.

        The legacy ``show_commands()`` is preserved for callers that still
        use the old API (``help <topic>`` mappings for the builder /
        cartridge contexts that cmd_help does not own).
        """
        topic = args[0].lower() if args else self.current_context
        # Deep-context contexts (`cartridges/tpm20`, `testruns/TC-001:once`,
        # `devices/rasp1`, …) share the same help block as the parent
        # menu — the deep shorthand is documented in the parent sub-help.
        if topic.startswith("cartridges/"):
            topic = "cartridges"
        elif topic.startswith("testruns/"):
            topic = "testruns"
        elif "/" in topic:
            parent, _, _ = topic.partition("/")
            if parent in self._DOMAIN_SPECS:
                topic = parent
        if topic in (
            "mcp",
            "tools",
            "operation",
            "cartridges",
            "testruns",
            "devices",
            "analysts",
            "users",
        ):
            self._render_subhelp(topic)
            return
        if topic:
            # Defer to the legacy multi-context help for unknown topics so
            # the existing builder/cartridge/backend help blocks still work.
            self.show_commands(topic)
            return

        table = Table(title="onoSendai Command Matrix", border_style="bright_blue")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_row(
            "mcp <subcommand>", "External MCP server management (try `help mcp`)"
        )
        table.add_row("tools <subcommand>", "AI tool inventory (try `help tools`)")
        table.add_row(
            "operation [create]",
            "Manage operations / persistence (try `help operation`)",
        )
        table.add_row(
            "devices <subcommand>",
            "Manage Devices in the operation (try `help devices`)",
        )
        table.add_row(
            "analysts <subcommand>",
            "Manage Analysts in the operation (try `help analysts`)",
        )
        table.add_row(
            "users <subcommand>",
            "Manage Users in the operation (try `help users`)",
        )
        table.add_row("show", "Print operation state as a tree")
        table.add_row(
            "cartridges <subcommand>",
            "Dynamic cartridge load/unload/run (try `help cartridges`)",
        )
        table.add_row(
            "testruns <subcommand>",
            "Test plan loading + run execution (try `help testruns`)",
        )
        table.add_row("ai <cmd>", "AI management and chat (try `help ai`)")
        table.add_row("backend", "Enter backend management menu")
        table.add_row("status", "Show operation status tree")
        table.add_row("vars <path>", "Inspect object variables")
        table.add_row("workspace switch <name>", "Switch active operation")
        table.add_row("back", "Exit current sub-menu")
        table.add_row("exit", "Disconnect from the matrix")
        self.rich_console.print(table)

    def _render_subhelp(self, topic: str) -> None:
        if topic == "mcp":
            table = Table(
                title="mcp — External MCP Server Management",
                border_style="bright_blue",
            )
            table.add_column("Sub-command", style="cyan")
            table.add_column("Usage", style="magenta")
            table.add_column("Description", style="white")
            table.add_row(
                "register",
                "mcp register <name> <cmd> [arg ...]",
                "Persist a server definition to ~/.wintermute/mcp_servers.json",
            )
            table.add_row(
                "list",
                "mcp list",
                "Show registered server definitions",
            )
            table.add_row(
                "delete",
                "mcp delete <name>",
                "Remove a registered server (stops it first if running)",
            )
            table.add_row(
                "start",
                "mcp start <name>",
                "Connect to a registered server (non-blocking; check `mcp status`)",
            )
            table.add_row(
                "stop",
                "mcp stop <name>",
                "Terminate a running session and force-kill the subprocess",
            )
            table.add_row(
                "status",
                "mcp status",
                "Show running sessions, PIDs, and exposed tool counts",
            )
            self.rich_console.print(table)
            return

        if topic == "tools":
            table = Table(title="tools — AI Tool Inventory", border_style="bright_blue")
            table.add_column("Sub-command", style="cyan")
            table.add_column("Usage", style="magenta")
            table.add_column("Description", style="white")
            table.add_row(
                "list",
                "tools list",
                "List native AI tools in the global registry",
            )
            table.add_row(
                "mcp",
                "tools mcp",
                "List tools exposed by connected MCP servers",
            )
            table.add_row(
                "load",
                "tools load <func>",
                "Register a Python callable as an AI tool",
            )
            self.rich_console.print(table)
            return

        if topic == "operation":
            table = Table(
                title="operation — Operation Deck", border_style="bright_blue"
            )
            table.add_column("Sub-command", style="cyan")
            table.add_column("Usage", style="magenta")
            table.add_column("Description", style="white")
            table.add_row(
                "(default)",
                "operation",
                "Enter the operation context",
            )
            table.add_row(
                "create",
                "operation create <name>",
                "Start a new operation",
            )
            table.add_row(
                "set",
                "set <key> <val>",
                "Inside `[operation]`, set name/start_date/end_date/ticket",
            )
            table.add_row("save", "save", "Persist operation to backend")
            table.add_row("load", "load <name>", "Load operation from backend")
            table.add_row("delete", "delete <name>", "Delete operation from backend")
            self.rich_console.print(table)
            return

        if topic in ("devices", "analysts", "users"):
            self._render_domain_subhelp(topic)
            return

        if topic == "cartridges":
            table = Table(
                title="cartridges — Dynamic Cartridge Manager",
                border_style="bright_blue",
            )
            table.add_column("Sub-command", style="cyan")
            table.add_column("Usage", style="magenta")
            table.add_column("Description", style="white")
            table.add_row(
                "list",
                "cartridges list",
                "Show available + currently loaded cartridges",
            )
            table.add_row(
                "load",
                "cartridges load <name>",
                "Import the module, instantiate it, register its public "
                "methods as AI tools",
            )
            table.add_row(
                "unload",
                "cartridges unload <name>",
                "Drop the instance and unregister its tools",
            )
            table.add_row(
                "run",
                "cartridges run <cartridge> <function> [args ...]",
                "Invoke a public method on a loaded cartridge "
                "(e.g. `cartridges run tpm20 test_pcr_state 0`)",
            )
            self.rich_console.print(table)
            return

        if topic == "testruns":
            table = Table(
                title="testruns — Test Run Execution",
                border_style="bright_blue",
            )
            table.add_column("Sub-command", style="cyan")
            table.add_column("Usage", style="magenta")
            table.add_column("Description", style="white")
            table.add_row(
                "load",
                "testruns load <path>",
                "Read a JSON TestPlan from disk and attach it to the active operation",
            )
            table.add_row(
                "generate",
                "testruns generate",
                "Materialise TestCaseRuns for every attached plan "
                "(skips runs that already exist)",
            )
            table.add_row(
                "list",
                "testruns list",
                "Show all runs with id / target / status (color-coded)",
            )
            table.add_row(
                "(drill)",
                "<run_id>",
                "Inside [testruns], typing a run_id like `TC-001:once` "
                "opens [testruns/<run_id>] for deep editing",
            )

            deep = Table(
                title="[testruns/<run_id>] — Deep Context",
                border_style="bright_magenta",
            )
            deep.add_column("Command", style="cyan")
            deep.add_column("Usage", style="magenta")
            deep.add_column("Description", style="white")
            deep.add_row(
                "show",
                "show",
                "Render the run's panel: test case, target, status, "
                "steps, notes, findings",
            )
            deep.add_row(
                "status",
                "status <state>",
                "Set the run to one of `not_run`, `in_progress`, "
                "`passed`, `failed`, `blocked`, `not_applicable`",
            )
            deep.add_row(
                "start / pass / fail",
                "start",
                "Shorthand for `status in_progress` / `passed` / "
                "`failed` (also calls start()/finish() on the run)",
            )
            deep.add_row(
                "note",
                'note "<text>"',
                "Append a free-text note to run.notes (newline-separated)",
            )
            deep.add_row(
                "vuln",
                'vuln "<title>" <cvss>',
                "Create a Vulnerability(title=…, cvss=…) and append it to run.findings",
            )

            self.rich_console.print(table)
            self.rich_console.print(deep)
            return

    def _render_domain_subhelp(self, domain: str) -> None:
        """Sub-help for the domain routers (`devices` / `analysts` /
        `users`).

        Renders the parent menu (list / add / edit / delete) and a deep
        context table that documents what `set` and (for devices) the
        nested `services` sub-commands accept.
        """
        spec = self._DOMAIN_SPECS[domain]
        entity = spec["entity_label"]
        id_attr = spec["id_attr"]
        inline = self._INLINE_ADD_SPECS.get(entity, {})
        inline_fields: List[str] = inline.get("fields", [])

        table = Table(
            title=f"{domain} — Operation Data",
            border_style="bright_blue",
        )
        table.add_column("Sub-command", style="cyan")
        table.add_column("Usage", style="magenta")
        table.add_column("Description", style="white")
        table.add_row(
            "list",
            f"{domain} list",
            f"Render every {entity} attached to the active operation",
        )
        if inline_fields:
            usage_args = " ".join(f"<{f}>" for f in inline_fields)
            table.add_row(
                "add",
                f"{domain} add {usage_args}",
                f"Append a new {entity}; partial args drop into the "
                "builder pre-populated",
            )
        else:
            table.add_row("add", f"{domain} add", f"Open a {entity} builder")
        table.add_row(
            "edit",
            f"{domain} edit <{id_attr}>",
            f"Open the deep editor for one {entity} "
            f"(prompt becomes [{domain}/<{id_attr}>])",
        )
        table.add_row(
            "delete",
            f"{domain} delete <{id_attr}>",
            f"Remove the {entity} with the given {id_attr}",
        )
        table.add_row(
            "(drill)",
            f"<{id_attr}>",
            f"Inside [{domain}], typing a known {id_attr} is a "
            f"shorthand for `edit <{id_attr}>`",
        )

        deep = Table(
            title=f"[{domain}/<{id_attr}>] — Deep Context",
            border_style="bright_magenta",
        )
        deep.add_column("Command", style="cyan")
        deep.add_column("Usage", style="magenta")
        deep.add_column("Description", style="white")
        deep.add_row(
            "show",
            "show",
            "Schema-aware Property/Type/Value table for the live "
            f"{entity}, with sub-tables for any nested collections",
        )
        deep.add_row(
            "set",
            "set <prop> <value>",
            f"Mutate the live {entity} via setattr (with int/bool/str type inference)",
        )

        # Dynamic nested-collection help is driven by the entity class's
        # ``__schema__``: any list-typed schema field becomes a CRUD
        # surface here. Hardcoding `services` for `devices` was the bug
        # the architect rejected — now we document every schema key the
        # operator can actually use.
        cls = self.ENTITY_CLASSES.get(entity)
        schema: Dict[str, Any] = (getattr(cls, "__schema__", {}) if cls else {}) or {}
        for key, member_class in schema.items():
            label = (
                member_class.__name__
                if isinstance(member_class, type)
                else str(member_class)
            )
            deep.add_row(
                f"{key} list",
                f"{key} list",
                f"List every {label} in `{entity}.{key}`",
            )
            deep.add_row(
                f"{key} add",
                f"{key} add [args ...]",
                f"Append a new {label}; bare `add` opens an interactive builder",
            )
            deep.add_row(
                f"{key} edit",
                f"{key} edit <id>",
                f"Drill into `[{domain}/<{id_attr}>/{key}/<id>]` to "
                f"edit a single {label}",
            )
            deep.add_row(
                f"{key} delete",
                f"{key} delete <id>",
                f"Remove a {label} by its human-readable id",
            )

        self.rich_console.print(table)
        self.rich_console.print(deep)

    def cmd_show(self) -> None:
        """Render the live operation as a fully ``__schema__``-driven
        Rich tree.

        Replaces the previous hardcoded analysts/devices/peripherals
        branches with a recursive walk over each object's
        ``__schema__``. Any list-typed schema field with at least one
        item becomes a folder-style sub-branch; every nested object
        recurses through its OWN ``__schema__`` so a Service's
        ``vulnerabilities`` and a Device's ``peripherals`` /
        ``vulnerabilities`` show up automatically — without the
        renderer having to know about them.
        """
        op = self.active_operation
        schema = getattr(op, "__schema__", {}) or {}

        # Empty-state check: no schema collection has any items. The
        # legacy "Operation is currently empty" wording is preserved
        # because existing UX tests + downstream tooling assert against
        # it verbatim.
        has_any = any(
            isinstance(getattr(op, key, None), list) and bool(getattr(op, key))
            for key in schema
        )
        if not has_any:
            self.rich_console.print("[!] Operation is currently empty.")
            return

        op_name = getattr(op, "operation_name", "<unnamed>")
        tree = Tree(f"[bold cyan]Operation:[/] {op_name}")
        self._build_tree_nodes(op, tree)
        self.rich_console.print(tree)

    def _build_tree_nodes(self, obj: Any, tree_branch: Any) -> None:
        """Recurse over ``obj.__schema__`` adding folder-style branches
        for every populated list-typed collection.

        Each item gets a label derived from
        :meth:`_human_label`'s fallback chain, then we recurse into
        the item itself so its own schema fields surface as deeper
        leaves. Scalars (e.g. ``Device.processor``) and empty
        collections are skipped so the tree stays focused on populated
        state.
        """
        schema = getattr(obj, "__schema__", {}) or {}
        for collection_name in schema:
            items = getattr(obj, collection_name, None)
            if not isinstance(items, list) or not items:
                continue
            sub_branch = tree_branch.add(
                f"[bold blue]{collection_name.capitalize()}[/]"
            )
            for item in items:
                item_branch = sub_branch.add(self._human_label(item))
                # Recurse — the item's own __schema__ drives deeper
                # nesting (Service.vulnerabilities, Device.peripherals,
                # …) without the renderer needing to know any specifics.
                self._build_tree_nodes(item, item_branch)

    @staticmethod
    def _human_label(obj: Any) -> str:
        """Best-effort human-readable label for a tree leaf.

        Walks the standard identifier-attribute fallback chain
        (``hostname``, ``name``, ``title``, ``portNumber``, ``userid``,
        ``id``) and returns the first non-empty value, or the class
        name as a last resort.
        """
        for attr in (
            "hostname",
            "name",
            "title",
            "portNumber",
            "userid",
            "id",
        ):
            value = getattr(obj, attr, None)
            if value is None or value == "":
                continue
            return str(value)
        return type(obj).__name__

    def cmd_add(self, input_string: str) -> None:
        """Strict-parse + append entity to the active operation.

        Uses :func:`shlex.split` so quoted strings (e.g. multi-word analyst
        names) survive intact: ``add analyst "foo bar" foobar foobar@x.com``
        becomes a single ``"foo bar"`` argument. If the entity type does not
        match a supported strict-parse path, the call falls through to the
        existing interactive builder via :meth:`cmd_add_enter`.
        """
        try:
            tokens = shlex.split(input_string)
        except ValueError as exc:
            self.rich_console.print(
                f"[red][!] Bad quoting in `add` arguments: {exc}[/]"
            )
            return

        # Tolerate callers that pass the full line (`add analyst …`) or just
        # the tail (`analyst …`). The first literal token is dropped if it
        # is the command name.
        if tokens and tokens[0].lower() == "add":
            tokens = tokens[1:]
        if not tokens:
            self.rich_console.print(
                "Usage: add <analyst|device|user|service> <args ...>"
            )
            return

        entity = tokens[0].lower()
        rest = tokens[1:]

        spec = self._INLINE_ADD_SPECS.get(entity)
        if spec is None:
            # Unsupported entity for inline-arg ingest — drop into the
            # plain interactive builder so paths like `add cloudaccount`
            # continue to work.
            self.cmd_add_enter(entity)
            return

        fields: List[str] = spec["fields"]
        required: int = spec["required"]

        if len(rest) > len(fields):
            self.rich_console.print(
                f"[red][!] Too many args for `add {entity}`. "
                f"Expected at most {len(fields)} ({', '.join(fields)}), "
                f"got {len(rest)}.[/]"
            )
            return

        if len(rest) >= required:
            # All required fields satisfied → bypass the interactive
            # builder and append directly.
            self._inline_append(entity, rest)
            return

        # Partial → enter the builder pre-populated with whatever the
        # operator already typed. Reusing cmd_builder_set gets type
        # inference (int/bool detection) and the user-visible "Set k=v"
        # echo for free.
        self.cmd_add_enter(entity)
        if not self.builder_stack:
            return
        for field, value in zip(fields, rest):
            self.cmd_builder_set(field, value)
        self.rich_console.print(
            f"[*] Pre-populated {len(rest)} of {required} required field(s). "
            "Use `set <key> <val>` to fill the rest, then `save`."
        )

    # Class-level table mapping entity → ordered field names + count of
    # leading args required for the strict-append fast path. Mirrors the
    # `help add` signatures so the documented and inline behavior agree.
    _INLINE_ADD_SPECS: ClassVar[Dict[str, Dict[str, Any]]] = {
        "analyst": {"fields": ["name", "userid", "email"], "required": 3},
        "device": {"fields": ["hostname", "ipaddr"], "required": 1},
        "user": {"fields": ["uid", "name", "email"], "required": 3},
        "service": {
            "fields": ["device_hostname", "portNumber", "app"],
            "required": 3,
        },
    }

    def _inline_append(self, entity: str, values: List[str]) -> None:
        """Build the entity straight from positional args and append it.

        Companion of :meth:`cmd_add`'s strict-append fast path. Each
        branch matches the corresponding row in
        :attr:`_INLINE_ADD_SPECS`.
        """
        op = self.active_operation

        if entity == "analyst":
            name, userid, email = values[:3]
            op.addAnalyst(name, userid, email)
            self.rich_console.print(
                f"[green]✔[/] Added analyst [bold]{name}[/] ({userid})"
            )
            return

        if entity == "device":
            hostname = values[0]
            ip = values[1] if len(values) >= 2 else "127.0.0.1"
            op.addDevice(hostname, ipaddr=ip)
            self.rich_console.print(
                f"[green]✔[/] Added device [bold]{hostname}[/] ({ip})"
            )
            return

        if entity == "user":
            uid, name, email = values[:3]
            op.addUser(uid, name, email, teams=[])
            self.rich_console.print(f"[green]✔[/] Added user [bold]{uid}[/] ({name})")
            return

        if entity == "service":
            host, port_str, app = values[:3]
            try:
                port = int(port_str)
            except ValueError:
                self.rich_console.print(
                    f"[red][!] Service port must be an integer, got {port_str!r}[/]"
                )
                return
            device = op.getDeviceByHostname(host)
            if device is None:
                self.rich_console.print(
                    f"[red][!] No device named {host!r} in this operation.[/]"
                )
                return
            service = Service(portNumber=port, app=app)
            device.services.append(service)
            self.rich_console.print(f"[green]✔[/] Added service {port}/{app} to {host}")
            return

    # --- Operation Data Domain Routers ------------------------------------
    #
    # Replaces the generic `add` menu, which couldn't route nested objects
    # cleanly (e.g. a `service` needs a parent `device`). The new top-level
    # commands (`devices`, `analysts`, `users`) drop the operator into a
    # domain context that knows how to list / add / edit / delete its own
    # objects, and the deep `[devices/<hostname>]` form unlocks live
    # editing including service management.

    # Domain → live operation collection / primary identifier / inline
    # append spec key. Source of truth for all domain routing.
    _DOMAIN_SPECS: ClassVar[Dict[str, Dict[str, str]]] = {
        "devices": {
            "collection": "devices",
            "id_attr": "hostname",
            "entity_label": "device",
        },
        "analysts": {
            "collection": "analysts",
            "id_attr": "userid",
            "entity_label": "analyst",
        },
        "users": {
            "collection": "users",
            "id_attr": "uid",
            "entity_label": "user",
        },
    }

    def cmd_domain(self, domain: str, args: List[str]) -> None:
        """Sub-dispatcher for the top-level domain routers.

        ``domain`` is one of ``devices``, ``analysts``, ``users``. With no
        args, falls through to ``list``. Otherwise routes ``list / add /
        edit / delete`` against :attr:`active_operation`.
        """
        if domain not in self._DOMAIN_SPECS:
            self.rich_console.print(f"[red][!] Unknown domain: {domain}[/]")
            return

        if not args:
            self._render_domain_list(domain)
            return

        sub = args[0].lower()
        rest = args[1:]

        if sub == "list":
            self._render_domain_list(domain)
            return

        if sub == "add":
            self._domain_add(domain, rest)
            return

        if sub == "edit":
            if len(rest) != 1:
                self.rich_console.print(f"Usage: {domain} edit <id>")
                return
            self._domain_edit(domain, rest[0])
            return

        if sub == "delete":
            if len(rest) != 1:
                self.rich_console.print(f"Usage: {domain} delete <id>")
                return
            self._domain_delete(domain, rest[0])
            return

        self.rich_console.print(
            f"[red][!] Unknown {domain} subcommand: {sub!r}[/]\n"
            f"Usage: {domain} <list|add|edit|delete> [args ...]"
        )

    def _render_domain_list(self, domain: str) -> None:
        spec = self._DOMAIN_SPECS[domain]
        items = list(getattr(self.active_operation, spec["collection"]))
        title_map = {
            "devices": "🖥️  Devices",
            "analysts": "🕵️  Analysts",
            "users": "👤 Users",
        }
        if domain == "devices":
            table = Table(title=title_map[domain], border_style="bright_blue")
            table.add_column("Hostname", style="cyan")
            table.add_column("IP", style="magenta")
            table.add_column("OS", style="white")
            table.add_column("Services", style="green", justify="right")
            table.add_column("Vulns", style="red", justify="right")
            if not items:
                table.add_row("[dim]none[/]", "", "", "", "")
            else:
                for d in items:
                    table.add_row(
                        getattr(d, "hostname", ""),
                        str(getattr(d, "ipaddr", "") or ""),
                        getattr(d, "operatingsystem", "") or "",
                        str(len(getattr(d, "services", []) or [])),
                        str(len(getattr(d, "vulnerabilities", []) or [])),
                    )
        elif domain == "analysts":
            table = Table(title=title_map[domain], border_style="bright_blue")
            table.add_column("UserID", style="cyan")
            table.add_column("Name", style="magenta")
            table.add_column("Email", style="white")
            if not items:
                table.add_row("[dim]none[/]", "", "")
            else:
                for a in items:
                    table.add_row(
                        getattr(a, "userid", ""),
                        getattr(a, "name", ""),
                        str(getattr(a, "email", "") or ""),
                    )
        else:  # users
            table = Table(title=title_map[domain], border_style="bright_blue")
            table.add_column("UID", style="cyan")
            table.add_column("Name", style="magenta")
            table.add_column("Email", style="white")
            if not items:
                table.add_row("[dim]none[/]", "", "")
            else:
                for u in items:
                    table.add_row(
                        getattr(u, "uid", ""),
                        getattr(u, "name", ""),
                        str(getattr(u, "email", "") or ""),
                    )
        self.rich_console.print(table)

    def _domain_add(self, domain: str, values: List[str]) -> None:
        """Route ``<domain> add ...`` to the existing inline-append /
        builder pre-populate flow.

        Synthesises the entity-typed token ``cmd_add`` expects so all the
        partial-args / strict-append / quoted-string handling we already
        built stays in one place.
        """
        spec = self._DOMAIN_SPECS[domain]
        entity_label = spec["entity_label"]
        if not values:
            # `<domain> add` with no values → empty interactive builder.
            self.cmd_add_enter(entity_label)
            return
        # Plain-space join (NOT shlex.quote!) so the round-trip
        # split-then-rejoin heals quoted multi-word args. The legacy
        # dispatcher relied on this exact behaviour: when the run() loop
        # split `analysts add "Foo Bar" jdoe …` on whitespace, the
        # quotes ended up as embedded characters in the tokens; rejoining
        # with spaces restores `"Foo Bar"` as a single shlex-parseable
        # unit.
        rebuilt = " ".join([entity_label, *values])
        self.cmd_add(rebuilt)

    # Fields the path resolver tries (in order) when looking up an object
    # by a human-typed identifier. Matches the kinds of strings an
    # operator naturally has on hand: hostnames, user ids, port numbers,
    # service names, vulnerability titles, etc.
    _HUMAN_ID_FIELDS: ClassVar[tuple[str, ...]] = (
        "id",
        "hostname",
        "name",
        "userid",
        "uid",
        "port",
        "portNumber",
        "app",
        "title",
        "ipaddr",
    )

    @classmethod
    def _find_by_human_id(cls, collection: List[Any], identifier: str) -> Optional[Any]:
        """Return the first object in ``collection`` whose any-of-known
        human-readable fields stringifies to ``identifier``.

        Used by every path-driven lookup (top-level domain edit, deep
        ``__schema__`` traversal, services-by-port, …) so a single
        traversal rule applies regardless of how nested the object is.
        ``None`` if nothing matches.
        """
        for obj in collection:
            for field in cls._HUMAN_ID_FIELDS:
                value = getattr(obj, field, None)
                if value is None or value == "":
                    continue
                if str(value) == identifier:
                    return obj
        return None

    def _resolve_live_path(self, path: str) -> Optional[Any]:
        """Walk a ``<collection>/<id>/<collection>/<id>/…`` path against
        the active operation and return the deepest live object.

        Each ``<collection>`` is resolved with ``getattr`` and each
        ``<id>`` via :meth:`_find_by_human_id`. A trailing collection
        with no identifier returns the collection list itself; a missing
        link in the chain returns ``None``. Used both to resolve the
        deep-context current_context AND for the ``back`` rewind path.
        """
        if not path:
            return self.active_operation
        parts = path.split("/")
        current: Any = self.active_operation
        i = 0
        while i < len(parts):
            collection_name = parts[i]
            if i + 1 >= len(parts):
                return getattr(current, collection_name, None)
            ident = parts[i + 1]
            collection = getattr(current, collection_name, None)
            if not isinstance(collection, list):
                return None
            nested = self._find_by_human_id(collection, ident)
            if nested is None:
                return None
            current = nested
            i += 2
        return current

    def _lookup_domain_object(self, domain: str, ident: str) -> Optional[Any]:
        """Top-level domain lookup.

        Forwards to :meth:`_find_by_human_id` so the same human-readable
        match rules apply at the root as in nested traversals.
        """
        spec = self._DOMAIN_SPECS[domain]
        collection = list(getattr(self.active_operation, spec["collection"]))
        return self._find_by_human_id(collection, ident)

    def _domain_edit(self, domain: str, ident: str) -> None:
        obj = self._lookup_domain_object(domain, ident)
        if obj is None:
            self.rich_console.print(
                f"[red][!] No {self._DOMAIN_SPECS[domain]['entity_label']} "
                f"with id {ident!r}.[/]"
            )
            return
        # Drilldown — the prompt flips to `[<domain>/<id>]` and the
        # contextual dispatcher takes over from here.
        self.current_context = f"{domain}/{ident}"
        self.rich_console.print(
            f"[*] Editing live [bold]{ident}[/] — `show` displays current "
            "state, `set <prop> <val>` mutates it, `back` returns."
        )

    def _domain_delete(self, domain: str, ident: str) -> None:
        spec = self._DOMAIN_SPECS[domain]
        collection: list[Any] = getattr(self.active_operation, spec["collection"])
        before = len(collection)
        collection[:] = [
            obj for obj in collection if getattr(obj, spec["id_attr"], None) != ident
        ]
        if len(collection) == before:
            self.rich_console.print(
                f"[yellow]No {spec['entity_label']} with id {ident!r} to delete.[/]"
            )
            return
        # If the operator was deep-editing this very object, pop them out.
        if self.current_context == f"{domain}/{ident}":
            self.current_context = domain
        self.rich_console.print(
            f"[green]✔[/] Removed {spec['entity_label']} [bold]{ident}[/]"
        )

    def _render_live_object_panel(self, obj: Any, label: str) -> None:
        """Schema-aware Property/Type/Value table for a *live* operation
        object (not a builder), with sub-tables for any nested service /
        vulnerability collections.
        """
        cls = type(obj)
        ident_label = self._object_identity(obj)
        table = Table(title=f"{label}: {ident_label}", border_style="bright_blue")
        table.add_column("Property", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Value", style="green")

        ordered, types = self._introspect_constructor_fields(cls)
        if not ordered:
            # Fall back to the live attribute set when introspection fails
            # (e.g. ad-hoc dynamic classes).
            ordered = [k for k in vars(obj) if not k.startswith("_")]
            for k in ordered:
                types.setdefault(k, type(getattr(obj, k)).__name__)

        nested_keys = {"services", "vulnerabilities", "peripherals"}
        for field_name in ordered:
            if field_name in nested_keys:
                # Render nested collections as their own tables below;
                # show only the count here so the main table stays readable.
                value = getattr(obj, field_name, None) or []
                table.add_row(
                    field_name,
                    types.get(field_name, ""),
                    f"[dim]{len(value)} item(s) — see sub-table[/]",
                )
                continue
            value = getattr(obj, field_name, None)
            if value is None or value == "":
                value_str = "[dim]<unset>[/]"
            else:
                value_str = self._format_property_value(value)
            table.add_row(field_name, types.get(field_name, ""), value_str)

        self.rich_console.print(table)

        # Sub-tables for nested collections.
        services = list(getattr(obj, "services", None) or [])
        if services:
            self._render_services_table(services)
        vulns = list(getattr(obj, "vulnerabilities", None) or [])
        if vulns:
            self._render_vulnerabilities_table(vulns)

    def _render_services_table(self, services: List[Any]) -> None:
        sub = Table(title="Services", border_style="bright_magenta")
        sub.add_column("Port", style="cyan", justify="right")
        sub.add_column("App", style="magenta")
        sub.add_column("Protocol", style="white")
        sub.add_column("Vulns", style="red", justify="right")
        for s in services:
            sub.add_row(
                str(getattr(s, "portNumber", "")),
                str(getattr(s, "app", "") or ""),
                str(getattr(s, "protocol", "") or ""),
                str(len(getattr(s, "vulnerabilities", []) or [])),
            )
        self.rich_console.print(sub)

    def _render_vulnerabilities_table(self, vulns: List[Any]) -> None:
        sub = Table(title="Vulnerabilities", border_style="red")
        sub.add_column("Title", style="cyan")
        sub.add_column("CVSS", style="magenta", justify="right")
        sub.add_column("Severity", style="white")
        for v in vulns:
            risk = getattr(v, "risk", None)
            severity = getattr(risk, "severity", "") if risk is not None else ""
            sub.add_row(
                str(getattr(v, "title", "") or ""),
                str(getattr(v, "cvss", "")),
                str(severity or ""),
            )
        self.rich_console.print(sub)

    @staticmethod
    def _object_identity(obj: Any) -> str:
        for attr in ("hostname", "userid", "uid", "name", "title"):
            value = getattr(obj, attr, None)
            if value:
                return str(value)
        return repr(obj)

    @staticmethod
    def _coerce_scalar_value(raw: str) -> str | int | bool:
        """Match :meth:`cmd_builder_set`'s int/bool/string inference for
        the live-object `set` path."""
        stripped = raw
        if len(stripped) >= 2 and (
            (stripped.startswith('"') and stripped.endswith('"'))
            or (stripped.startswith("'") and stripped.endswith("'"))
        ):
            stripped = stripped[1:-1]
        if stripped.isdigit():
            return int(stripped)
        if stripped.lower() == "true":
            return True
        if stripped.lower() == "false":
            return False
        return stripped

    def _set_live_attr(self, obj: Any, prop: str, raw_value: str) -> None:
        coerced = self._coerce_scalar_value(raw_value)
        try:
            setattr(obj, prop, coerced)
        except Exception as exc:
            self.rich_console.print(f"[red][!] Failed to set {prop}: {exc}[/]")
            return
        self.rich_console.print(f"[*] Set {prop} = {coerced}")

    # --- Schema-driven nested collection dispatcher ----------------------

    def _dispatch_nested_schema(
        self, live_object: Any, schema_key: str, args: List[str]
    ) -> bool:
        """Handle ``<schema_key> list|add|edit|delete`` against a live
        object's ``__schema__``-declared collection.

        ``live_object.__schema__[schema_key]`` is the *target class* used
        when adding new members (resolved from forward-reference strings
        if necessary). The actual list is always
        ``getattr(live_object, schema_key)``.

        This replaces the previous hardcoded services sub-dispatcher so
        every collection registered in any model's ``__schema__``
        (peripherals, vulnerabilities, findings, test_cases, …) gets the
        same uniform CRUD surface.
        """
        schema: Dict[str, Any] = getattr(live_object, "__schema__", {}) or {}
        target_class = schema.get(schema_key)
        if target_class is None:
            return False
        if isinstance(target_class, str):
            resolved = self._resolve_forward_class(target_class, type(live_object))
            if resolved is None:
                self.rich_console.print(
                    f"[red][!] Could not resolve forward-reference "
                    f"{target_class!r} for {schema_key}.[/]"
                )
                return True
            target_class = resolved

        target_collection = getattr(live_object, schema_key, None)
        if not isinstance(target_collection, list):
            # Schema entries that are scalar (e.g. ``processor`` on
            # Device) don't fit the list-CRUD surface. Surface a hint
            # instead of pretending we handled it.
            self.rich_console.print(
                f"[yellow]{schema_key!r} on "
                f"{type(live_object).__name__} is scalar, not a "
                "collection — use `set` instead.[/]"
            )
            return True

        if not args:
            self._render_collection_table(target_collection, schema_key, target_class)
            return True

        sub = args[0].lower()
        rest = args[1:]

        if sub == "list":
            self._render_collection_table(target_collection, schema_key, target_class)
            return True

        if sub == "edit":
            if len(rest) != 1:
                self.rich_console.print(f"Usage: {schema_key} edit <id>")
                return True
            nested = self._find_by_human_id(target_collection, rest[0])
            if nested is None:
                self.rich_console.print(
                    f"[red][!] No {schema_key} entry matching {rest[0]!r}.[/]"
                )
                return True
            self.current_context = f"{self.current_context}/{schema_key}/{rest[0]}"
            self.rich_console.print(
                f"[*] Editing live [bold]{rest[0]}[/] — `show` displays "
                "current state, `set <prop> <val>` mutates it, `back` "
                "returns."
            )
            return True

        if sub == "delete":
            if len(rest) != 1:
                self.rich_console.print(f"Usage: {schema_key} delete <id>")
                return True
            nested = self._find_by_human_id(target_collection, rest[0])
            if nested is None:
                self.rich_console.print(
                    f"[yellow]No {schema_key} entry matching {rest[0]!r} to delete.[/]"
                )
                return True
            target_collection.remove(nested)
            # If the operator was deep-editing this very object, pop
            # the context one level up so the prompt reflects reality.
            doomed_path = f"{self.current_context}/{schema_key}/{rest[0]}"
            if self.current_context.startswith(doomed_path):
                # Pop the last `<schema_key>/<id>` pair.
                parts = self.current_context.split("/")
                self.current_context = "/".join(parts[:-2])
            self.rich_console.print(
                f"[green]✔[/] Removed {schema_key} entry [bold]{rest[0]}[/]"
            )
            return True

        if sub == "add":
            return self._dispatch_schema_add(
                target_class, target_collection, rest, schema_key
            )

        self.rich_console.print(f"[red][!] Unknown {schema_key} subcommand: {sub!r}[/]")
        return True

    def _dispatch_schema_add(
        self,
        target_class: type,
        target_collection: List[Any],
        values: List[str],
        schema_key: str,
    ) -> bool:
        """Strict-append fast path / partial-args builder for any class
        registered in a parent's ``__schema__``.

        ``values`` are zipped against ``target_class.__init__`` parameter
        order with int/bool/str coercion. With ALL required fields
        satisfied we construct + append directly; otherwise we drop into
        a builder pre-populated with whatever the operator typed,
        anchored to ``target_collection`` so the eventual ``save``
        commits to that live list.
        """
        ordered, _types = self._introspect_constructor_fields(target_class)
        if not ordered:
            self.rich_console.print(
                f"[red][!] Cannot introspect {target_class.__name__} constructor.[/]"
            )
            return True
        required_count = self._required_param_count(target_class)

        if len(values) > len(ordered):
            self.rich_console.print(
                f"[red][!] Too many args for `{schema_key} add`. "
                f"Expected at most {len(ordered)} ({', '.join(ordered)}), "
                f"got {len(values)}.[/]"
            )
            return True

        # Empty add when the class has any fields → drop into the
        # interactive builder rather than silently appending an
        # all-defaults instance.
        if not values:
            self.cmd_add_enter(
                target_class.__name__.lower(),
                cls=target_class,
                target_collection=target_collection,
            )
            return True

        if len(values) >= required_count:
            kwargs: Dict[str, Any] = {}
            for name, raw in zip(ordered, values):
                kwargs[name] = self._coerce_scalar_value(raw)
            try:
                obj = target_class(**kwargs)
            except Exception as exc:
                self.rich_console.print(
                    f"[red][!] Failed to construct {target_class.__name__}: {exc}[/]"
                )
                return True
            target_collection.append(obj)
            self.rich_console.print(
                f"[green]✔[/] Added {target_class.__name__} "
                f"[bold]{self._object_identity(obj)}[/] to {schema_key}"
            )
            return True

        # Partial → builder pre-populated.
        self.cmd_add_enter(
            target_class.__name__.lower(),
            cls=target_class,
            target_collection=target_collection,
        )
        if not self.builder_stack:
            return True
        for name, value in zip(ordered, values):
            self.cmd_builder_set(name, value)
        self.rich_console.print(
            f"[*] Pre-populated {len(values)} of {required_count} "
            "required field(s). Use `set <key> <val>` to fill the rest, "
            "then `save`."
        )
        return True

    @staticmethod
    def _required_param_count(target_class: type) -> int:
        try:
            sig = inspect.signature(target_class)
        except (TypeError, ValueError):
            return 0
        count = 0
        for name, param in sig.parameters.items():
            if name in ("self", "args", "kwargs"):
                continue
            if param.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            if param.default is inspect.Parameter.empty:
                count += 1
        return count

    @staticmethod
    def _resolve_forward_class(
        ref: str, hint_cls: Optional[type] = None
    ) -> Optional[type]:
        """Resolve a string forward-reference (used in ``__schema__``
        for self-referential models like ``TestPlan``)."""
        if hint_cls is not None and hint_cls.__name__ == ref:
            return hint_cls
        if hint_cls is not None:
            module = inspect.getmodule(hint_cls)
            if module is not None:
                resolved = getattr(module, ref, None)
                if isinstance(resolved, type):
                    return resolved
        return None

    def _render_collection_table(
        self,
        items: List[Any],
        schema_key: str,
        target_class: type,
    ) -> None:
        """Schema-driven render: column per constructor field (capped at
        4 for compactness) plus an empty-state hint."""
        if not items:
            self.rich_console.print(f"[yellow]No {schema_key} attached.[/]")
            return
        ordered, _types = self._introspect_constructor_fields(target_class)
        # Fall back to the live attribute set when introspection fails
        # (rare; covers ad-hoc dynamic classes).
        if not ordered:
            sample = items[0]
            ordered = [k for k in vars(sample) if not k.startswith("_")]
        shown = ordered[:4]
        table = Table(
            title=f"{schema_key.capitalize()} ({target_class.__name__})",
            border_style="bright_blue",
        )
        for col in shown:
            table.add_column(col, style="cyan")
        for item in items:
            row = [self._format_property_value(getattr(item, col, "")) for col in shown]
            table.add_row(*row)
        self.rich_console.print(table)

    # --- Cartridge Manager (replaces legacy `use`) -------------------------

    def cmd_cartridges(self, args: List[str]) -> None:
        """Dispatcher for ``cartridges <list|load|unload|run> [...]``.

        Backed by :class:`wintermute.cartridges.manager.CartridgeManager`,
        which owns dynamic import + AI tool registration. Designed so a
        single command — ``cartridges run tpm20 test_pcr_state 0`` —
        invokes any public method on a loaded cartridge directly from the
        REPL.
        """
        from wintermute.cartridges.manager import CartridgeManager

        manager = CartridgeManager()

        if not args:
            self.rich_console.print(
                "Usage: cartridges <list|load|unload|run> [args ...]  "
                "(try `help cartridges`)"
            )
            return

        sub = args[0].lower()
        rest = args[1:]

        if sub == "list":
            if rest:
                # `cartridges list <name>` — deep inspection of a single
                # cartridge: render every public function with its
                # type-hinted signature and docstring summary.
                self._render_cartridge_detail(manager, rest[0])
            else:
                self._render_cartridges_list(manager)
            return

        if sub == "load":
            if len(rest) != 1:
                self.rich_console.print("Usage: cartridges load <name>")
                return
            name = rest[0]
            try:
                loaded = manager.load(name)
            except ModuleNotFoundError:
                self.rich_console.print(
                    f"[red][!] Cartridge {name!r} not found. "
                    "Run `cartridges list` for available modules.[/]"
                )
                return
            except Exception as exc:
                self.rich_console.print(
                    f"[red][!] Failed to load cartridge {name!r}: {exc}[/]"
                )
                return
            if loaded:
                tool_names = manager.tool_names_for(name)
                self.rich_console.print(
                    f"[green]✔[/] Loaded cartridge [bold]{name}[/] "
                    f"— {len(tool_names)} tool(s) registered with the AI."
                )
                if tool_names:
                    # Verbose surface so the operator immediately sees what
                    # functions are now callable via `cartridges run` (or
                    # via the deep context `[cartridges/<name>]`).
                    self.rich_console.print(
                        f"[*] Exposed functions: [cyan]{', '.join(tool_names)}[/]"
                    )
            else:
                self.rich_console.print(
                    f"[yellow]Cartridge {name!r} was already loaded.[/]"
                )
            return

        if sub == "unload":
            if len(rest) != 1:
                self.rich_console.print("Usage: cartridges unload <name>")
                return
            name = rest[0]
            if manager.unload(name):
                self.rich_console.print(
                    f"[green]✔[/] Unloaded cartridge [bold]{name}[/]"
                )
            else:
                self.rich_console.print(f"[yellow]Cartridge {name!r} is not loaded.[/]")
            return

        if sub == "run":
            if len(rest) < 2:
                self.rich_console.print(
                    "Usage: cartridges run <cartridge> <function> [args ...]"
                )
                return
            self._run_cartridge_function(manager, rest[0], rest[1], rest[2:])
            return

        self.rich_console.print(
            f"[red][!] Unknown cartridges subcommand: {sub!r}[/]\n"
            "Usage: cartridges <list|load|unload|run> [args ...]"
        )

    def _render_cartridges_list(self, manager: Any) -> None:
        available = manager.list_available()
        loaded = set(manager.list_loaded())

        avail_table = Table(title="📦 Available Cartridges", border_style="bright_blue")
        avail_table.add_column("Name", style="cyan")
        avail_table.add_column("Loaded", style="green")
        if not available:
            avail_table.add_row("[dim]none[/]", "")
        else:
            for name in available:
                avail_table.add_row(name, "✔" if name in loaded else "")
        self.rich_console.print(avail_table)

        loaded_table = Table(title="🟢 Loaded Cartridges", border_style="bright_blue")
        loaded_table.add_column("Name", style="cyan")
        loaded_table.add_column("Class", style="magenta")
        loaded_table.add_column("Tools", style="green", justify="right")
        if not loaded:
            loaded_table.add_row("[dim]none[/]", "", "")
        else:
            for name in manager.list_loaded():
                instance = manager.loaded_cartridges[name]
                tool_count = len(manager.tool_names_for(name))
                loaded_table.add_row(name, type(instance).__name__, str(tool_count))
        self.rich_console.print(loaded_table)

    def _render_cartridge_detail(self, manager: Any, name: str) -> None:
        """Print every public function on the named cartridge.

        If the cartridge is not currently loaded the user gets a focused
        hint instead of an empty table — the cartridge can be available
        on disk but not yet instantiated.
        """
        if name not in manager.list_loaded():
            if name in manager.list_available():
                self.rich_console.print(
                    f"[yellow]Cartridge {name!r} is available but not loaded — "
                    f"run `cartridges load {name}` first.[/]"
                )
            else:
                self.rich_console.print(f"[red][!] Cartridge {name!r} not found.[/]")
            return

        instance = manager.loaded_cartridges[name]
        tool_names = manager.tool_names_for(name)
        table = Table(
            title=f"⚙️ Cartridge: {name} ({type(instance).__name__})",
            border_style="bright_blue",
        )
        table.add_column("Function", style="cyan")
        table.add_column("Signature", style="magenta")
        table.add_column("Description", style="white")

        if not tool_names:
            table.add_row("[dim]no public functions exposed[/]", "", "")
            self.rich_console.print(table)
            return

        for tool_name in tool_names:
            method = getattr(instance, tool_name, None)
            if method is None or not callable(method):
                continue
            try:
                sig = inspect.signature(method)
                sig_str = str(sig)
            except (TypeError, ValueError):
                sig_str = "(...)"
            doc = (getattr(method, "__doc__", "") or "").strip()
            first_line = doc.splitlines()[0] if doc else ""
            if len(first_line) > 80:
                first_line = first_line[:77] + "…"
            table.add_row(tool_name, sig_str, first_line)
        self.rich_console.print(table)

    def _run_cartridge_function(
        self,
        manager: Any,
        cartridge_name: str,
        function_name: str,
        raw_args: List[str],
    ) -> None:
        """Invoke a single public method on a loaded cartridge.

        The trailing ``raw_args`` are joined and re-shlex'd so quoted
        strings (``cartridges run x foo "multi word"``) survive. Numeric
        annotations are coerced via the function's type hints so callers
        can pass ``0`` instead of ``"0"`` for an ``int`` parameter.
        """
        try:
            instance = manager.get(cartridge_name)
        except KeyError:
            self.rich_console.print(
                f"[red][!] Cartridge {cartridge_name!r} is not loaded. "
                f"Try `cartridges load {cartridge_name}` first.[/]"
            )
            return

        if function_name.startswith("_"):
            self.rich_console.print(
                f"[red][!] {function_name!r} is private; only public methods "
                "can be invoked via `cartridges run`.[/]"
            )
            return

        try:
            func = getattr(instance, function_name)
        except AttributeError:
            self.rich_console.print(
                f"[red][!] Cartridge {cartridge_name!r} has no method "
                f"{function_name!r}.[/]"
            )
            return
        if not callable(func):
            self.rich_console.print(
                f"[red][!] {function_name!r} on {cartridge_name!r} is not callable.[/]"
            )
            return

        try:
            tokens = shlex.split(" ".join(raw_args)) if raw_args else []
        except ValueError as exc:
            self.rich_console.print(f"[red][!] Bad quoting in run arguments: {exc}[/]")
            return

        coerced = self._coerce_run_args(func, tokens)

        try:
            result = func(*coerced)
        except Exception as exc:
            self.rich_console.print(
                f"[red][!] {cartridge_name}.{function_name} raised: {exc}[/]"
            )
            return

        self.rich_console.print(result)

    @staticmethod
    def _coerce_run_args(func: Any, raw: List[str]) -> List[Any]:
        """Best-effort positional argument coercion using ``func``'s hints."""
        from typing import get_type_hints

        try:
            hints = get_type_hints(func)
            sig = inspect.signature(func)
        except Exception:
            return list(raw)

        params = [p for n, p in sig.parameters.items() if n != "self"]
        out: List[Any] = []
        for idx, value in enumerate(raw):
            if idx >= len(params):
                out.append(value)
                continue
            target = hints.get(params[idx].name, str)
            try:
                if target is bool:
                    out.append(value.lower() in ("true", "1", "yes", "on"))
                elif target is int:
                    out.append(int(value, 0))  # supports "0x..." literals
                elif target is float:
                    out.append(float(value))
                elif target is bytes:
                    out.append(value.encode("utf-8"))
                else:
                    out.append(value)
            except (ValueError, TypeError):
                out.append(value)
        return out

    # --- Test Run Management -----------------------------------------------

    # Status -> rich color mapping for the run table / detail panel.
    _RUN_STATUS_STYLE: ClassVar[Dict[str, str]] = {
        "not_run": "white",
        "in_progress": "yellow",
        "passed": "green",
        "failed": "red",
        "blocked": "magenta",
        "not_applicable": "dim",
    }

    def _find_test_run(self, run_id: str) -> Optional[TestCaseRun]:
        for run in self.active_operation.test_runs:
            if run.run_id == run_id:
                return run
        return None

    def _find_test_case(self, code: str) -> Optional[TestCase]:
        for tc in self.active_operation.iterTestCases():
            if tc.code == code:
                return tc
        return None

    def cmd_testruns(self, args: List[str]) -> None:
        """Dispatcher for ``testruns <load|generate|list> [...]``.

        Backed by the live ``self.active_operation``. Designed so the
        operator can drive the full execution flow (load plan → generate
        runs → list runs → drill into one → update status / attach
        findings) without ever leaving the REPL.
        """
        if not args:
            self.rich_console.print(
                "Usage: testruns <load|generate|list> [args ...]  (try `help testruns`)"
            )
            return

        sub = args[0].lower()
        rest = args[1:]

        if sub == "load":
            if len(rest) != 1:
                self.rich_console.print("Usage: testruns load <path>")
                return
            self._cmd_testruns_load(rest[0])
            return

        if sub == "generate":
            created = self.active_operation.generateTestRuns(replace=False)
            self.rich_console.print(
                f"[green]✔[/] Generated [bold]{len(created)}[/] new test "
                f"run(s). Total runs: {len(self.active_operation.test_runs)}."
            )
            return

        if sub == "list":
            self._render_test_runs_list()
            return

        self.rich_console.print(
            f"[red][!] Unknown testruns subcommand: {sub!r}[/]\n"
            "Usage: testruns <load|generate|list> [args ...]"
        )

    def _cmd_testruns_load(self, path: str) -> None:
        target = Path(path).expanduser()
        if not target.is_file():
            self.rich_console.print(f"[red][!] File not found: {target}[/]")
            return
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except Exception as exc:
            self.rich_console.print(f"[red][!] Failed to parse {target}: {exc}[/]")
            return
        try:
            plan = TestPlan.from_dict(data)
        except Exception as exc:
            self.rich_console.print(
                f"[red][!] {target} is not a valid TestPlan: {exc}[/]"
            )
            return
        added = self.active_operation.addTestPlan(plan)
        if added:
            self.rich_console.print(
                f"[green]✔[/] Loaded test plan [bold]{plan.code}[/] "
                f"({len(plan.test_cases)} test case(s))."
            )
        else:
            self.rich_console.print(
                f"[yellow]Test plan {plan.code!r} is already attached.[/]"
            )

    def _render_test_runs_list(self) -> None:
        runs = list(self.active_operation.test_runs)
        if not runs:
            self.rich_console.print(
                "[yellow]No test runs yet — load a plan with "
                "`testruns load <path>` then `testruns generate`.[/]"
            )
            return
        table = Table(title="🧪 Test Runs", border_style="bright_blue")
        table.add_column("Run ID", style="cyan")
        table.add_column("Test Case", style="magenta")
        table.add_column("Bound / Target", style="white")
        table.add_column("Status", style="white")
        for run in runs:
            target = (
                ", ".join(f"{b.alias}={b.object_id}" for b in run.bound)
                or "[dim]once[/]"
            )
            status_color = self._RUN_STATUS_STYLE.get(run.status.value, "white")
            table.add_row(
                run.run_id,
                run.test_case_code,
                target,
                f"[{status_color}]{run.status.value}[/]",
            )
        self.rich_console.print(table)

    def _render_test_run_detail(self, run_id: str) -> None:
        run = self._find_test_run(run_id)
        if run is None:
            self.rich_console.print(f"[red][!] No test run with id {run_id!r}.[/]")
            return
        tc = self._find_test_case(run.test_case_code)

        target = (
            "\n".join(f"  • {b.alias} ({b.kind}) → {b.object_id}" for b in run.bound)
            or "  • once"
        )
        status_color = self._RUN_STATUS_STYLE.get(run.status.value, "white")

        lines: List[str] = []
        if tc is not None:
            lines.append(f"[bold]Test Case:[/] {tc.code} — {tc.name}")
            if tc.description:
                lines.append(f"[bold]Description:[/] {tc.description}")
        else:
            lines.append(
                f"[bold]Test Case:[/] {run.test_case_code} "
                "[dim](case not found in attached plans)[/]"
            )
        lines.append(f"[bold]Bound Target:[/]\n{target}")
        lines.append(f"[bold]Status:[/] [{status_color}]{run.status.value}[/]")
        lines.append(
            f"[bold]Started:[/] {run.started_at.isoformat() if run.started_at else '—'}"
        )
        lines.append(
            f"[bold]Ended:[/] {run.ended_at.isoformat() if run.ended_at else '—'}"
        )
        lines.append(f"[bold]Executed by:[/] {run.executed_by or '—'}")

        if tc is not None and tc.steps:
            step_lines = [
                f"  {i}. {step.title or step.action or '(unnamed)'}"
                for i, step in enumerate(tc.steps, 1)
            ]
            lines.append("[bold]Reproduction Steps:[/]\n" + "\n".join(step_lines))

        notes = run.notes or "[dim]none[/]"
        lines.append(f"[bold]Notes:[/]\n{notes}")

        if run.findings:
            finding_lines = [f"  • {v.title} (CVSS {v.cvss})" for v in run.findings]
            lines.append("[bold]Findings:[/]\n" + "\n".join(finding_lines))
        else:
            lines.append("[bold]Findings:[/] [dim]none[/]")

        self.rich_console.print(
            Panel(
                "\n".join(lines),
                title=f"🧪 {run.run_id}",
                border_style="bright_blue",
            )
        )

    def _set_run_status(self, run_id: str, state: str) -> None:
        run = self._find_test_run(run_id)
        if run is None:
            self.rich_console.print(f"[red][!] No test run with id {run_id!r}.[/]")
            return
        try:
            new_status = RunStatus(state)
        except ValueError:
            valid = ", ".join(s.value for s in RunStatus)
            self.rich_console.print(
                f"[red][!] Invalid status {state!r}. Valid: {valid}[/]"
            )
            return
        run.status = new_status
        if new_status == RunStatus.in_progress:
            run.start()
        elif new_status in (
            RunStatus.passed,
            RunStatus.failed,
            RunStatus.blocked,
            RunStatus.not_applicable,
        ):
            run.finish()
        color = self._RUN_STATUS_STYLE.get(new_status.value, "white")
        self.rich_console.print(
            f"[green]✔[/] Run [bold]{run_id}[/] → [{color}]{new_status.value}[/]"
        )

    def _append_run_note(self, run_id: str, note: str) -> None:
        run = self._find_test_run(run_id)
        if run is None:
            self.rich_console.print(f"[red][!] No test run with id {run_id!r}.[/]")
            return
        # `notes` is a single string field; append with a newline so each
        # note is on its own line for the eventual report.
        run.notes = f"{run.notes}\n{note}" if run.notes else note
        self.rich_console.print(f"[green]✔[/] Note appended to [bold]{run_id}[/]")

    def _attach_run_vulnerability(
        self, run_id: str, title: str, cvss: int, description: str = ""
    ) -> None:
        run = self._find_test_run(run_id)
        if run is None:
            self.rich_console.print(f"[red][!] No test run with id {run_id!r}.[/]")
            return
        vuln = Vulnerability(title=title, cvss=cvss, description=description)
        run.findings.append(vuln)
        self.rich_console.print(
            f"[green]✔[/] Attached vulnerability [bold]{title}[/] "
            f"(CVSS {cvss}) to [bold]{run_id}[/]"
        )

    def cmd_testrun_action(self, run_id: str, raw_input: str) -> None:
        """Deep-context handler invoked from `[testruns/<run_id>]`.

        ``raw_input`` is the entire post-command string; this method
        re-shlexes it so quoted arguments (note "<text>", vuln
        "<title>") survive intact.
        """
        try:
            tokens = shlex.split(raw_input)
        except ValueError as exc:
            self.rich_console.print(f"[red][!] Bad quoting in arguments: {exc}[/]")
            return
        if not tokens:
            self.rich_console.print(
                "Usage: <show|status|start|pass|fail|note|vuln> ..."
            )
            return

        action = tokens[0].lower()
        rest = tokens[1:]

        if action == "show":
            self._render_test_run_detail(run_id)
            return

        if action == "status":
            if len(rest) != 1:
                valid = ", ".join(s.value for s in RunStatus)
                self.rich_console.print(f"Usage: status <{valid}>")
                return
            self._set_run_status(run_id, rest[0])
            return

        if action in ("start", "pass", "fail"):
            mapping = {
                "start": RunStatus.in_progress.value,
                "pass": RunStatus.passed.value,
                "fail": RunStatus.failed.value,
            }
            self._set_run_status(run_id, mapping[action])
            return

        if action == "note":
            if not rest:
                self.rich_console.print('Usage: note "<text>"')
                return
            self._append_run_note(run_id, " ".join(rest))
            return

        if action == "vuln":
            if len(rest) != 2:
                self.rich_console.print('Usage: vuln "<title>" <cvss>')
                return
            title = rest[0]
            try:
                cvss = int(rest[1])
            except ValueError:
                self.rich_console.print(
                    f"[red][!] CVSS must be an integer, got {rest[1]!r}[/]"
                )
                return
            self._attach_run_vulnerability(run_id, title, cvss)
            return

        self.rich_console.print(f"[red][!] Unknown deep-context command: {action!r}[/]")

    # --- Local AI Tools (bound to active_operation) ------------------------
    #
    # Registered into the global tool registry from `__init__`. The Local
    # Console AI cannot use the MCP ``ObjectRegistry`` (different process,
    # different state), so these closures expose the live operation to the
    # `tool_calling_chat` flow.

    def ai_list_test_runs(self) -> dict[str, Any]:
        """List every TestCaseRun attached to the active operation.

        Returns:
            A dictionary with ``total`` (int) and ``runs`` (list of
            ``{run_id, test_case_code, status, executed_by, bound}``
            entries). ``bound`` is itself a list of
            ``{alias, kind, object_id}`` describing each target the
            run is bound to.
        """
        runs = self.active_operation.test_runs
        return {
            "total": len(runs),
            "runs": [
                {
                    "run_id": r.run_id,
                    "test_case_code": r.test_case_code,
                    "status": r.status.value,
                    "executed_by": r.executed_by,
                    "bound": [
                        {
                            "alias": b.alias,
                            "kind": b.kind,
                            "object_id": b.object_id,
                        }
                        for b in r.bound
                    ],
                }
                for r in runs
            ],
        }

    def ai_get_run_details(self, run_id: str) -> dict[str, Any]:
        """Return the full state of a single test run by id.

        Args:
            run_id: Identifier from :func:`ai_list_test_runs`
                (e.g. ``"TC-001:once"`` or ``"TC-002:dev01:eth0"``).

        Returns:
            A dictionary with the run's fields plus the parent test
            case's name / description / step count, or
            ``{"error": "..."}`` if no run with that id exists.
        """
        run = self._find_test_run(run_id)
        if run is None:
            return {"error": f"no test run with id {run_id!r}"}
        tc = self._find_test_case(run.test_case_code)
        out: dict[str, Any] = {
            "run_id": run.run_id,
            "test_case_code": run.test_case_code,
            "status": run.status.value,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
            "executed_by": run.executed_by,
            "notes": run.notes,
            "bound": [
                {"alias": b.alias, "kind": b.kind, "object_id": b.object_id}
                for b in run.bound
            ],
            "findings": [
                {"title": v.title, "cvss": v.cvss, "vuln_id": v.vuln_id}
                for v in run.findings
            ],
        }
        if tc is not None:
            out["test_case"] = {
                "name": tc.name,
                "description": tc.description,
                "step_count": len(tc.steps),
            }
        return out

    def ai_update_run_status(self, run_id: str, status: str) -> dict[str, Any]:
        """Update a test run's status, calling start()/finish() as appropriate.

        Args:
            run_id: Identifier from :func:`ai_list_test_runs`.
            status: One of ``"not_run"``, ``"in_progress"``, ``"passed"``,
                ``"failed"``, ``"blocked"``, ``"not_applicable"``.
                ``"in_progress"`` calls :meth:`TestCaseRun.start` (sets
                ``started_at``); any terminal status calls
                :meth:`TestCaseRun.finish` (sets ``ended_at``).

        Returns:
            ``{"run_id", "status"}`` on success, or ``{"error": "..."}``.
        """
        run = self._find_test_run(run_id)
        if run is None:
            return {"error": f"no test run with id {run_id!r}"}
        try:
            new_status = RunStatus(status)
        except ValueError:
            valid = [s.value for s in RunStatus]
            return {
                "error": f"invalid status {status!r}",
                "valid": valid,
            }
        run.status = new_status
        if new_status == RunStatus.in_progress:
            run.start()
        elif new_status in (
            RunStatus.passed,
            RunStatus.failed,
            RunStatus.blocked,
            RunStatus.not_applicable,
        ):
            run.finish()
        return {"run_id": run_id, "status": new_status.value}

    def ai_add_run_note(self, run_id: str, note: str) -> dict[str, Any]:
        """Append a free-text note to a test run, separated by newline.

        Args:
            run_id: Identifier from :func:`ai_list_test_runs`.
            note: Text to append.

        Returns:
            ``{"run_id", "notes_length"}`` on success, or
            ``{"error": "..."}``.
        """
        run = self._find_test_run(run_id)
        if run is None:
            return {"error": f"no test run with id {run_id!r}"}
        run.notes = f"{run.notes}\n{note}" if run.notes else note
        return {"run_id": run_id, "notes_length": len(run.notes)}

    def cmd_tools(self, *args: str) -> None:
        if not args:
            self.rich_console.print("Usage: tools <list|mcp|load> [args]")
            return

        sub = args[0].lower()
        if sub == "list":
            tools_dict = global_tool_registry._tools
            if not tools_dict:
                self.rich_console.print(
                    "[yellow]No native AI tools registered. "
                    "Load one with `tools load <func>`.[/]"
                )
                return
            # Cross-reference with the MCP manager so duplicates (when the
            # MCP server has registered into the global registry too) are
            # tagged correctly.
            external_names: set[str] = set()
            try:
                external_names = {
                    spec.name for spec in self.mcp_manager.get_all_external_tools()
                }
            except Exception:
                pass
            table = Table(title="🧰 Native AI Tools", border_style="bright_blue")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="white")
            table.add_column("Source", style="magenta")
            for name, tool in tools_dict.items():
                desc = tool.description or ""
                short = (desc[:80] + "…") if len(desc) > 80 else desc
                source = "mcp" if name in external_names else "internal"
                table.add_row(name, short, source)
            self.rich_console.print(table)
            return

        elif sub == "mcp":
            specs = self.mcp_manager.get_all_external_tools()
            if not specs:
                self.rich_console.print(
                    "[yellow]No external MCP tools available — "
                    "start a server with `mcp start <name>`.[/]"
                )
                return
            table = Table(title="🔌 External MCP Tools", border_style="bright_blue")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="white")
            table.add_column("Server", style="magenta")
            for spec in specs:
                # Names from MCPClientManager are namespaced as `<server>__<tool>`.
                server, _, _ = spec.name.partition("__")
                desc = spec.description or ""
                short = (desc[:80] + "…") if len(desc) > 80 else desc
                table.add_row(spec.name, short, server or "unknown")
            self.rich_console.print(table)
            return

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

    # --- MCP Client Manager Sub-menu ---

    def cmd_mcp(self, *args: str) -> None:
        """Dispatcher for `mcp register|list|delete|start|stop|status`."""
        if not args:
            self.rich_console.print(
                "Usage: mcp <register|list|delete|start|stop|status> [...]"
            )
            return

        sub = args[0].lower()
        rest = args[1:]

        if sub == "register":
            if len(rest) < 2:
                self.rich_console.print(
                    "Usage: mcp register <name> <command> [arg ...]"
                )
                return
            name, command = rest[0], rest[1]
            extra = list(rest[2:])
            try:
                defn = self.mcp_manager.register_server(
                    name=name, command=command, args=extra
                )
            except Exception as exc:
                self.rich_console.print(
                    f"[red][!] Failed to register MCP server {name!r}: {exc}[/]"
                )
                return
            self.rich_console.print(
                f"[*] Registered MCP server [bold green]{defn.name}[/] "
                f"({defn.command} {' '.join(defn.args)})"
            )
            self.rich_console.print(f"    Saved to {self.mcp_manager.config_path}")

        elif sub == "list":
            registered = self.mcp_manager.list_registered()
            if not registered:
                self.rich_console.print(
                    "[yellow]No MCP servers registered. "
                    "Add one with `mcp register <name> <command> [args...]`.[/]"
                )
                return
            table = Table(title="🔌 Registered MCP Servers", border_style="bright_blue")
            table.add_column("Name", style="cyan")
            table.add_column("Command", style="magenta")
            table.add_column("Args", style="white")
            for defn in registered:
                table.add_row(defn.name, defn.command, " ".join(defn.args))
            self.rich_console.print(table)

        elif sub == "delete":
            if len(rest) != 1:
                self.rich_console.print("Usage: mcp delete <name>")
                return
            name = rest[0]
            removed = self.mcp_manager.delete_server(name)
            if removed:
                self.rich_console.print(f"[*] Removed MCP server [bold green]{name}[/]")
            else:
                self.rich_console.print(
                    f"[yellow]No registered MCP server named {name!r}.[/]"
                )

        elif sub == "start":
            if len(rest) != 1:
                self.rich_console.print("Usage: mcp start <name>")
                return
            name = rest[0]
            # start_server returns immediately with a status string; the
            # actual stdio handshake happens on the manager's daemon
            # thread. Use `mcp status` to confirm the connection is up.
            message = self.mcp_manager.start_server(name)
            self.rich_console.print(f"[*] {message}")

        elif sub == "stop":
            if len(rest) != 1:
                self.rich_console.print("Usage: mcp stop <name>")
                return
            name = rest[0]
            message = self.mcp_manager.stop_server(name)
            self.rich_console.print(f"[*] {message}")

        elif sub == "status":
            running = self.mcp_manager.get_status()
            if not running:
                self.rich_console.print("[yellow]No MCP servers currently running.[/]")
                return
            table = Table(title="📡 Running MCP Servers", border_style="bright_blue")
            table.add_column("Name", style="cyan")
            table.add_column("PID", style="white", justify="right")
            table.add_column("Command", style="magenta")
            table.add_column("Args", style="white")
            table.add_column("Tools", style="green", justify="right")
            for sess in running:
                table.add_row(
                    sess["name"],
                    str(sess.get("pid", "")),
                    sess["command"],
                    " ".join(sess["args"]),
                    str(sess["tools"]),
                )
            self.rich_console.print(table)

        else:
            self.rich_console.print(
                f"[red][!] Unknown mcp subcommand: {sub!r}[/]\n"
                "Usage: mcp <register|list|delete|start|stop|status> [...]"
            )

    # --- Main Loop ---

    # Commands that must NEVER be intercepted by contextual routing — even
    # when the user is inside a sub-menu. Most of these short-circuit in
    # `run()` before reaching this dispatcher; `show` is the one that
    # actually flows through here, but listing the others defensively keeps
    # the rule in one place.
    _SAFETY_COMMANDS = frozenset(
        {"back", "exit", "help", "show", "status", "workspace"}
    )

    def _dispatch_builder_command(self, cmd: str, args: List[str]) -> bool:
        """Dispatch a single command while a builder is active on the stack.

        Returns ``True`` when the command was consumed by the builder
        flow (``set`` / ``show`` / ``save`` / ``create`` / ``add ...``).
        Returns ``False`` for everything else so the run() loop can fall
        through to the global handlers.

        Extracted from the previously-inlined BUILDER CONTEXT HANDLER so
        the locked-down ``add`` fallback can be exercised by tests
        without reproducing the dispatcher logic.
        """
        if cmd == "set" and len(args) >= 2:
            self.cmd_builder_set(args[0], " ".join(args[1:]))
            return True
        if cmd == "show":
            self.cmd_builder_show()
            return True
        if cmd in ("save", "create"):
            self.cmd_builder_save()
            return True
        if cmd == "add" and args:
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
                    self.rich_console.print(f"[*] Constructing {p_type} node...")
                else:
                    self.rich_console.print(
                        f"[red][!] Unknown peripheral type: {p_type}[/]"
                    )
                return True

            # Check for 'add vulnerability'
            if args[0] == "vulnerability":
                from wintermute.findings import Vulnerability

                self.builder_stack.append(
                    BuilderContext(
                        "vulnerability",
                        Vulnerability,
                        parent_list_name="vulnerabilities",
                    )
                )
                self.rich_console.print("[*] Constructing vulnerability node...")
                return True

            # Check for cloud nested types (AWS only)
            if (
                args[0].lower() in self.CLOUD_NESTED_MAP
                and self._is_cloud_builder_aws()
            ):
                cloud_cls, parent_list = self.CLOUD_NESTED_MAP[args[0].lower()]
                self.builder_stack.append(
                    BuilderContext(
                        args[0].lower(),
                        cloud_cls,
                        parent_list_name=parent_list,
                    )
                )
                self.rich_console.print(f"[*] Constructing {args[0].lower()} node...")
                return True

            # Locked down: any unrecognised `add <type>` while inside a
            # builder used to silently stack a brand-new builder via
            # ``cmd_add_enter(args[0])`` — that produced the "Russian
            # doll" trap where a typo like `add user ...` inside a
            # `device` builder quietly nested an unrelated user builder
            # with the inline args dropped on the floor. Now we refuse
            # explicitly so the operator gets feedback instead of silent
            # corruption.
            self.rich_console.print(
                f"[red][!] Cannot add '{args[0]}' directly "
                f"into a {self.builder_stack[-1].entity_name} "
                "builder.[/]"
            )
            return True

        # Anything else (e.g. global commands) — let run() fall through
        # to the regular handlers.
        return False

    async def _dispatch_contextual(self, cmd: str, args: List[str]) -> bool:
        """Route ``cmd`` based on :attr:`current_context`.

        Returns ``True`` when the command was handled by a contextual
        rule. ``False`` means "fall through to the regular dispatcher".

        Two contexts have meaningful sub-routing today:

        * ``[cartridges]``: ``list/load/unload/run`` go straight to
          :meth:`cmd_cartridges`; typing the *name* of a loaded cartridge
          drills down into ``[cartridges/<name>]``.
        * ``[cartridges/<name>]``: ``list``, ``run``, and ``unload``
          implicitly carry the cartridge name so the user can type
          ``run test_pcr_state 0`` without re-naming the cartridge.
        """
        from wintermute.cartridges.manager import CartridgeManager

        manager = CartridgeManager()

        if self.current_context == "cartridges":
            if cmd in ("list", "load", "unload", "run"):
                self.cmd_cartridges([cmd, *args])
                return True
            # Drill into a loaded cartridge: e.g. inside `[cartridges]`,
            # typing `tpm20` becomes `[cartridges/tpm20]` so the operator
            # can issue bare `run test_pcr_state 0`.
            if cmd in manager.list_loaded():
                self.current_context = f"cartridges/{cmd}"
                return True
            return False

        if self.current_context.startswith("cartridges/"):
            cart_name = self.current_context.split("/", 1)[1]
            if cmd == "list":
                self.cmd_cartridges(["list", cart_name])
                return True
            if cmd == "run":
                self.cmd_cartridges(["run", cart_name, *args])
                return True
            if cmd == "unload":
                self.cmd_cartridges(["unload", cart_name])
                # Pop one level up so the prompt reflects reality.
                self.current_context = "cartridges"
                return True
            return False

        if self.current_context == "testruns":
            if cmd in ("load", "generate", "list"):
                self.cmd_testruns([cmd, *args])
                return True
            # Drill into a specific run by id (e.g. `TC-001:once`).
            existing_ids = {r.run_id for r in self.active_operation.test_runs}
            if cmd in existing_ids:
                self.current_context = f"testruns/{cmd}"
                return True
            return False

        if self.current_context.startswith("testruns/"):
            run_id = self.current_context.split("/", 1)[1]
            # Reconstruct the original token stream so quoted args (e.g.
            # `note "multi word"`) survive through cmd_testrun_action.
            raw = " ".join(args)
            if cmd in ("show", "status", "start", "pass", "fail", "note", "vuln"):
                self.cmd_testrun_action(run_id, f"{cmd} {raw}".strip())
                return True
            return False

        # ----- Operation Data Domain Routers --------------------------
        # Top-level domain contexts let the operator manage Operation
        # data (devices / analysts / users) cleanly without the broken
        # generic `add` menu.

        if self.current_context in self._DOMAIN_SPECS:
            domain = self.current_context
            if cmd in ("list", "add", "edit", "delete"):
                self.cmd_domain(domain, [cmd, *args])
                # `edit <id>` drilled the prompt down to `<domain>/<id>`;
                # for `add` / `list` / `delete` we stay in the domain.
                return True
            # Bare-id drilldown — typing `rasp1` inside `[devices]` is a
            # muscle-memory shortcut for `edit rasp1` (matches the
            # cartridges / testruns drilldown pattern).
            obj = self._lookup_domain_object(domain, cmd)
            if obj is not None:
                self.current_context = f"{domain}/{cmd}"
                return True
            return False

        if "/" in self.current_context:
            domain = self.current_context.split("/", 1)[0]
            if domain in self._DOMAIN_SPECS:
                live_object = self._resolve_live_path(self.current_context)
                if live_object is None:
                    # Some link in the path was deleted out from under us.
                    # Pop the deepest <key>/<id> pair until we land on an
                    # ancestor that still exists (or the root domain).
                    parts = self.current_context.split("/")
                    while len(parts) > 1:
                        parts = parts[:-2] if len(parts) >= 4 else [parts[0]]
                        candidate = "/".join(parts)
                        resolved = (
                            self.active_operation
                            if not candidate
                            else self._resolve_live_path(candidate)
                        )
                        if resolved is not None or candidate == domain:
                            self.current_context = candidate or domain
                            break
                    else:
                        self.current_context = domain
                    self.rich_console.print(
                        f"[yellow]Object at path "
                        f"{self.current_context!r} no longer exists; "
                        f"returning to [{self.current_context or 'root'}].[/]"
                    )
                    return True

                if cmd == "show":
                    self._render_live_object_panel(
                        live_object,
                        type(live_object).__name__.lower(),
                    )
                    return True

                if cmd == "set":
                    if len(args) < 2:
                        self.rich_console.print("Usage: set <prop> <value>")
                        return True
                    self._set_live_attr(live_object, args[0], " ".join(args[1:]))
                    return True

                # Schema-driven nested routing: ANY collection registered
                # in ``live_object.__schema__`` becomes a CRUD surface
                # (e.g. peripherals / vulnerabilities / services / etc.).
                schema = getattr(live_object, "__schema__", {}) or {}
                if cmd in schema:
                    return self._dispatch_nested_schema(live_object, cmd, list(args))

                return False

        return False

    async def _dispatch_main_commands(self, cmd: str, args: List[str]) -> bool:
        """Handlers for Main Menu / Global functional commands.

        Contextual routing runs first so commands typed inside a sub-menu
        (``list`` inside ``[cartridges]``, ``run test_pcr_state 0`` inside
        ``[cartridges/tpm20]``, …) reach the right handler instead of
        falling through to "unknown command". Safety commands listed in
        :attr:`_SAFETY_COMMANDS` always bypass this layer.
        """
        # Narrow exception: inside `[testruns/<run_id>]`, `show` and
        # `status` mean "this run", not the global operation tree. Hoist
        # them above the safety filter so the operator's intent matches
        # the visible prompt. Other safety commands (back, exit, help)
        # still bypass.
        if self.current_context.startswith("testruns/") and cmd in (
            "show",
            "status",
        ):
            run_id = self.current_context.split("/", 1)[1]
            raw = " ".join(args)
            self.cmd_testrun_action(run_id, f"{cmd} {raw}".strip())
            return True

        # Same hoist for the new domain deep contexts: inside
        # `[devices/<hostname>]`, `[analysts/<userid>]`, or
        # `[users/<uid>]`, `show` means the live object's panel — not
        # the global operation tree. The deep-context router in
        # `_dispatch_contextual` knows what to do; we just need to make
        # sure it gets the chance.
        if cmd == "show" and "/" in self.current_context:
            domain, _, _ = self.current_context.partition("/")
            if domain in self._DOMAIN_SPECS:
                handled = await self._dispatch_contextual(cmd, args)
                if handled:
                    return True

        if cmd not in self._SAFETY_COMMANDS:
            handled = await self._dispatch_contextual(cmd, args)
            if handled:
                return True

        if cmd == "operation":
            self.current_context = "operation"
            if args and args[0] == "create":
                self.cmd_operation_create(args[1] if len(args) > 1 else "default")
            else:
                self.cmd_operation_enter()
            return True

        elif cmd in self._DOMAIN_SPECS:
            # Top-level domain routers: `devices`, `analysts`, `users`.
            # The legacy generic `add` menu is gone — operators discover
            # supported entity types per domain via `help <domain>`.
            self.current_context = cmd
            self.cmd_domain(cmd, list(args))
            return True

        elif cmd == "edit" and len(args) >= 1:
            self.cmd_edit(" ".join(args))
            return True

        elif cmd == "delete" and len(args) >= 1:
            self.cmd_delete(" ".join(args))
            return True

        elif cmd == "cartridges":
            # New dynamic cartridge manager — replaces the legacy `use`
            # command. Sets the [cartridges] context for the prompt and
            # routes load/unload/list/run via cmd_cartridges.
            self.current_context = "cartridges"
            self.cmd_cartridges(args)
            return True

        elif cmd == "testruns":
            # Test-run sub-menu: load plans, generate runs, drill into a
            # specific run for status / notes / findings updates.
            self.current_context = "testruns"
            self.cmd_testruns(args)
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
                # Bare `show` — print the operation tree. The previous
                # implementation silently fell through to context-specific
                # branches (cartridge options / cmd_status) which left the
                # user staring at an empty prompt when no cartridge was
                # loaded. Now we always emit something.
                self.cmd_show()
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

        elif cmd == "tools":
            # Bare `tools` lands in the [tools] sub-menu; with args we
            # stay in whatever context we were in but still update so
            # `help` resolves to the tools sub-help.
            self.current_context = "tools"
            if args:
                self.cmd_tools(*args)
            else:
                self.rich_console.print(
                    "Usage: tools <list|mcp|load> [args]  (try `help tools`)"
                )
            return True

        elif cmd == "mcp":
            self.current_context = "mcp"
            self.cmd_mcp(*args)
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

    def _render_prompt(self) -> HTML:
        """Build the prompt-toolkit HTML string from the current state.

        Resolution order (highest priority first):

        1. **Active builder.** When :attr:`builder_stack` is non-empty the
           operator is mid-construction; surface that with
           ``[build:<entity>]`` so a typo like ``add user ...`` inside a
           ``device`` builder doesn't silently stack a Russian doll.
        2. **Sub-menu marker.** :attr:`current_context` (e.g. ``mcp``,
           ``cartridges``, ``testruns``).
        3. **Root.** Bare deck prompt.
        """
        if self.builder_stack:
            active = self.builder_stack[-1].entity_name
            return HTML(f"<b>onoSendai</b> <ansicyan>[build:{active}]</ansicyan> &gt; ")
        if self.current_context:
            return HTML(
                f"<b>onoSendai</b> <ansicyan>[{self.current_context}]</ansicyan> &gt; "
            )
        return HTML("<b>onoSendai</b> &gt; ")

    async def run(self) -> None:
        self.display_banner()

        while True:
            completer = self.update_completer()
            try:
                with patch_stdout():
                    user_input = await self.session.prompt_async(
                        self._render_prompt,
                        completer=completer,
                        style=self.style,
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
                    self.cmd_help(args)
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
                    handled = self._dispatch_builder_command(cmd, args)

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
