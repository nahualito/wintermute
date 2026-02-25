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
from wintermute.backends.bugzilla import BugzillaBackend
from wintermute.backends.docx_reports import DocxTplPerVulnBackend
from wintermute.backends.json_storage import JsonFileBackend
from wintermute.core import AWSAccount, Device, Operation, Service, User
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
        self.ENTITY_CLASSES = {
            "device": Device,
            "user": User,
            "awsaccount": AWSAccount,
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

        self.PERIPHERAL_MAP = {
            "uart": UART,
            "jtag": JTAG,
            "tpm": TPM,
            "ethernet": Ethernet,
            "wifi": Wifi,
            "bluetooth": Bluetooth,
            "usb": USB,
            "pcie": PCIe,
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
                "prompt": "bold cyan",
                "context": "bold yellow",
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
                                                                    
         OFFENSIVE SECURITY FRAMEWORK & HARDWARE AUDIT SUITE
        """
        self.rich_console.print(Panel(banner, style="bold red", expand=False))
        self.rich_console.print(
            f"[bold cyan]Workspace:[/] {self.operation.operation_name}"
        )
        if self.current_cartridge_name:
            self.rich_console.print(
                f"[bold yellow]Active Cartridge:[/] {self.current_cartridge_name}"
            )
        self.rich_console.print("")

    def get_prompt_tokens(self) -> List[tuple[str, str]]:
        tokens: List[tuple[str, str]] = [("class:prompt", "wintermute ")]

        # Check Context Stack
        current_ctx = self.context_stack[-1]

        if self.current_cartridge_name:
            tokens.append(("class:context", f"exploit({self.current_cartridge_name})"))
        elif hasattr(self, "builder_stack") and self.builder_stack:
            # Show active builder context
            active_builder = self.builder_stack[-1].entity_name
            tokens.append(("class:context", f"add({active_builder})"))
        elif current_ctx == "operation":
            tokens.append(
                ("class:context", f"operation({self.operation.operation_name})")
            )
        elif current_ctx == "backend":
            tokens.append(("class:context", "backend"))

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

            # Dynamic 'set' suggestions using inspect.signature
            set_suggestions: Dict[str, Any] = {}
            if target_cls:
                try:
                    sig = inspect.signature(target_cls.__init__)
                    for name, param in sig.parameters.items():
                        if name in ["self", "args", "kwargs"]:
                            continue
                        set_suggestions[name] = None
                except Exception:
                    pass

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

            return NestedCompleter.from_nested_dict(builder_commands)

        current_context = self.context_stack[-1]

        # Common commands available everywhere
        common_commands: Dict[str, Any] = {
            "help": None,
            "exit": None,
            "back": None,
            "status": None,
            "workspace": {
                "switch": None,
            },
            "add": {
                "analyst": None,
                "device": None,
                "user": None,
                "service": None,
                "awsaccount": None,
            },
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
                    "awsaccount": None,
                },
                "use": {c: None for c in self.available_cartridges},
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

            # Dynamic lists for edit command completion
            edit_targets = {
                "device": {d.hostname: None for d in self.operation.devices},
                "user": {u.uid: None for u in self.operation.users},
                "awsaccount": {
                    a.name: None
                    for a in self.operation.awsaccounts
                    if hasattr(a, "name")
                },
            }

            base_commands["edit"] = edit_targets

            if self.current_cartridge_name:
                base_commands["set"] = {opt: None for opt in self.cartridge_options}
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
            }
            return NestedCompleter.from_nested_dict(op_commands)

        # Fallback
        return NestedCompleter.from_nested_dict(common_commands)

    # --- Global Commands ---

    def cmd_operation_create(self, name: str) -> None:
        self.operation = Operation(operation_name=name)
        self.rich_console.print(
            f"[*] Created new operation context: [bold cyan]{name}[/]"
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

    def cmd_status(self) -> None:
        """Render a cyberpunk status tree of the current operation."""
        op = self.operation

        # Root Node
        root = Tree(
            f"[bold cyan]Operation: {op.operation_name}[/] [dim](ID: {op.operation_id})[/]"
        )

        # Branch: Analysts
        analysts_branch = root.add(f"[bold magenta]Analysts[/] ({len(op.analysts)})")
        for a in op.analysts:
            analysts_branch.add(f"[green]{a.name}[/] [dim]({a.userid})[/]")

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
                    peri_branch.add(f"{p_name} ({p_type})")

            # Show Services
            if d.services:
                svc_branch = d_node.add(f"[yellow]Services[/] ({len(d.services)})")
                for s in d.services:
                    svc_branch.add(f"{s.portNumber}/{s.protocol} ({s.app})")

            # Show Vulnerabilities
            if d.vulnerabilities:
                vuln_branch = d_node.add(
                    f"[red]Vulnerabilities[/] ({len(d.vulnerabilities)})"
                )
                for v in d.vulnerabilities:
                    vuln_branch.add(f"{v.title} (CVSS: {v.cvss})")

        # Branch: Users
        users_branch = root.add(f"[bold magenta]Users[/] ({len(op.users)})")
        for u in op.users:
            users_branch.add(f"[green]{u.uid}[/]")

        # Branch: Cloud Accounts
        cloud_branch = root.add(
            f"[bold magenta]Cloud Accounts[/] ({len(op.cloud_accounts)})"
        )
        for acc in op.cloud_accounts:
            name = getattr(acc, "name", "Unknown")
            aid = getattr(acc, "account_id", "No ID")
            cloud_branch.add(f"[green]{name}[/] [dim]({aid})[/]")

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

    def cmd_add_awsaccount(self, name: str, account_id: str) -> None:
        if self.operation.addAWSAccount(name, account_id=account_id):
            self.rich_console.print(f"[+] Added AWS Account: {name} ({account_id})")

    def cmd_edit_enter(self, entity_type: str, identifier: str) -> None:
        """Enters builder context populated with existing entity data."""
        etype = entity_type.lower()
        # Initialize with explicit type to avoid Mypy inference issues
        target_obj: Device | User | AWSAccount | Service | None = None

        # 1. Locate the object
        if etype == "device":
            target_obj = self.operation.getDeviceByHostname(identifier)
        elif etype == "user":
            target_obj = next(
                (u for u in self.operation.users if u.uid == identifier),
                None,
            )
        elif etype == "awsaccount":
            target_obj = next(
                (
                    a
                    for a in self.operation.awsaccounts
                    if getattr(a, "name", "") == identifier
                    or getattr(a, "account_id", "") == identifier
                ),
                None,
            )

        if not target_obj:
            self.rich_console.print(
                f"[red][!] Could not find {entity_type} '{identifier}'[/]"
            )
            return

        # 2. Extract properties
        props = {}
        for k, v in target_obj.__dict__.items():
            if not k.startswith("_"):
                props[k] = v

        # 3. Enter Builder
        cls = self.ENTITY_CLASSES.get(etype)
        ctx = BuilderContext(etype, entity_class=cls)
        ctx.properties = props
        self.builder_stack.append(ctx)
        self.rich_console.print(
            f"[*] Editing {entity_type} '{identifier}' (Builder Mode)"
        )

    # --- Builder Context ---

    def cmd_builder_set(self, key: str, value: str) -> None:
        """Sets a property in the current builder context."""
        if not self.builder_stack:
            return

        active_builder = self.builder_stack[-1]

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

        try:
            # 1. Instantiate Object if class is mapped
            entity_obj = None
            if cls:
                # Filter unknown kwargs to avoid __init__ errors if strict
                # For now assume user set valid keys via autocomplete
                entity_obj = cls(**data)
            else:
                # If no class mapped (e.g. device/user/service handled via dict/Operation)
                # we keep it as data dict
                entity_obj = data

            # 2. Check if Root or Nested
            # If stack length is 1, we are at root level (about to be popped)
            if len(self.builder_stack) == 1:
                # --- ROOT LEVEL SAVE ---
                if not entity_obj:
                    self.rich_console.print(
                        f"[red][!] Could not instantiate class for {target}.[/]"
                    )
                    return

                success = False
                if target == "device" and isinstance(entity_obj, Device):
                    # Ensure all nested items from data (builder properties) are in entity_obj
                    # This ensures peripherals/vulnerabilities are attached before saving to operation
                    entity_obj.peripherals = data.get(
                        "peripherals", entity_obj.peripherals
                    )
                    entity_obj.vulnerabilities = data.get(
                        "vulnerabilities", entity_obj.vulnerabilities
                    )
                    entity_obj.services = data.get("services", entity_obj.services)

                    if self.operation.addDevice(
                        hostname=entity_obj.hostname,
                        ipaddr=entity_obj.ipaddr,
                        macaddr=entity_obj.macaddr,
                        operatingsystem=entity_obj.operatingsystem,
                        fqdn=entity_obj.fqdn,
                        services=entity_obj.services,
                        peripherals=entity_obj.peripherals,
                        vulnerabilities=entity_obj.vulnerabilities,
                    ):
                        self.rich_console.print(
                            f"[bold green]✔[/] Saved Device: {entity_obj.hostname}"
                        )
                        success = True
                    else:
                        self.rich_console.print("[red][!] Failed to save device.")

                elif target == "user" and isinstance(entity_obj, User):
                    # Ensure vulnerabilities are attached
                    entity_obj.vulnerabilities = data.get(
                        "vulnerabilities", entity_obj.vulnerabilities
                    )

                    if self.operation.addUser(
                        uid=entity_obj.uid,
                        name=entity_obj.name,
                        email=entity_obj.email,
                        teams=entity_obj.teams,
                        dept=entity_obj.dept,
                        permissions=entity_obj.permissions,
                        override_reason=entity_obj.override_reason,
                        desktops=entity_obj.desktops,
                        ldap_groups=entity_obj.ldap_groups,
                        cloud_accounts=entity_obj.cloud_accounts,
                        vulnerabilities=entity_obj.vulnerabilities,
                    ):
                        self.rich_console.print(
                            f"[bold green]✔[/] Saved User: {entity_obj.uid}"
                        )
                        success = True
                    else:
                        self.rich_console.print("[red][!] Failed to save user.")

                elif target == "awsaccount" and isinstance(entity_obj, AWSAccount):
                    # Check match by ID or Name
                    e_acc_id = getattr(entity_obj, "account_id", None)
                    e_name = getattr(entity_obj, "name", "")
                    existing_acc = next(
                        (
                            a
                            for a in self.operation.awsaccounts
                            if (getattr(a, "account_id", None) == e_acc_id and e_acc_id)
                            or getattr(a, "name", "") == e_name
                        ),
                        None,
                    )
                    if existing_acc:
                        self.operation._merge_attributes(existing_acc, entity_obj)
                        self.rich_console.print(
                            f"[bold green]✔[/] Updated AWS Account: {e_name}"
                        )
                    else:
                        self.operation.cloud_accounts.append(entity_obj)
                        self.rich_console.print(
                            f"[bold green]✔[/] Created AWS Account: {e_name}"
                        )
                    success = True

                elif target == "service" and isinstance(entity_obj, Service):
                    # For Service at root, we still need context of WHERE to put it.
                    # The builder context might have 'device_hostname' if set manually.
                    dev_host = data.get("device_hostname")
                    if dev_host:
                        dev = self.operation.getDeviceByHostname(str(dev_host))
                        if dev:
                            # Merge logic for Service is: add if not exists
                            # Check if service exists
                            existing_svc = next(
                                (
                                    s
                                    for s in dev.services
                                    if s.portNumber == entity_obj.portNumber
                                    and s.protocol == entity_obj.protocol
                                ),
                                None,
                            )
                            if existing_svc:
                                self.operation._merge_attributes(
                                    existing_svc, entity_obj
                                )
                                self.rich_console.print(
                                    f"[bold green]✔[/] Updated Service on {dev_host}"
                                )
                            else:
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
                    self.rich_console.print(
                        f"[red][!] Cannot save {target} at root level (unsupported type).[/]"
                    )
                    return

                if success:
                    self.cmd_back()  # Pops the builder from stack

            else:
                # --- NESTED LEVEL SAVE ---
                # We are nested. The parent is at index -2.
                parent_builder = self.builder_stack[-2]
                parent_cls = parent_builder.entity_class

                # Determine target field name
                # 1. Use explicit parent_list_name if set (e.g. 'peripherals')
                # 2. Fallback to entity name (e.g. 'processor')
                field_name = active_builder.parent_list_name or target

                # Determine if field is a list or scalar using introspection
                is_list_field = False

                # A) Explicit override check
                if active_builder.parent_list_name:
                    is_list_field = True

                # B) Schema inspection
                elif parent_cls:
                    try:
                        sig = inspect.signature(parent_cls.__init__)
                        if field_name in sig.parameters:
                            param = sig.parameters[field_name]
                            if param.annotation != inspect.Parameter.empty:
                                type_str = str(param.annotation)
                                # crude check for list/sequence/iterable types
                                if any(
                                    x in type_str.lower()
                                    for x in ["list", "sequence", "iterable"]
                                ):
                                    is_list_field = True
                    except Exception:
                        pass

                # Apply changes
                if is_list_field:
                    if field_name not in parent_builder.properties:
                        parent_builder.properties[field_name] = []

                    # Safety check: ensure it IS a list
                    if not isinstance(parent_builder.properties[field_name], list):
                        # Convert scalar to list if needed (shouldn't happen with proper usage)
                        existing = parent_builder.properties[field_name]
                        parent_builder.properties[field_name] = (
                            [existing] if existing else []
                        )

                    parent_builder.properties[field_name].append(entity_obj)
                    self.rich_console.print(
                        f"[bold green]✔[/] Attached {target} to parent list '{field_name}'."
                    )
                else:
                    # Single assignment (handles processor, architecture, etc.)
                    parent_builder.properties[field_name] = entity_obj
                    self.rich_console.print(
                        f"[bold green]✔[/] Set parent field '{field_name}' = {target}"
                    )

                self.cmd_back()

        except Exception as e:
            self.rich_console.print(f"[red][!] Builder error: {e}[/]")

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
        self.rich_console.print(f"[*] Entering builder for {entity_type}...")

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

    def cmd_use(self, cartridge_name: str) -> None:
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
            self.current_cartridge_instance = None  # Wait for 'run' or initialization

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

            self.rich_console.print(
                f"[*] Loaded cartridge: [bold yellow]{cartridge_name}[/]"
            )
        except Exception as e:
            self.rich_console.print(f"[red][!] Error loading cartridge: {e}[/]")

    def cmd_set(self, option: str, value: str) -> None:
        if not self.current_cartridge_name:
            self.rich_console.print(
                "[red][!] No cartridge selected. Use 'use <cartridge>' first.[/]"
            )
            return
        if option not in self.cartridge_options:
            self.rich_console.print(f"[red][!] Unknown option: {option}[/]")
            return

        # Try to cast value if possible (crude)
        if value.isdigit():
            self.cartridge_options[option] = int(value)
        elif value.lower() in ["true", "false"]:
            self.cartridge_options[option] = value.lower() == "true"
        else:
            self.cartridge_options[option] = value

        self.rich_console.print(f"{option} => {value}")

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
                self.rich_console.print(f"[*] Running {self.current_cartridge_name}...")
                self.current_cartridge_instance.run()
            else:
                self.rich_console.print(
                    f"[*] Cartridge {self.current_cartridge_name} instantiated. Use dynamic commands to interact."
                )
        except Exception as e:
            self.rich_console.print(f"[red][!] Execution error: {e}[/]")

    # --- Information & Help ---

    def show_options(self) -> None:
        if not self.current_cartridge_name:
            self.rich_console.print("[red][!] No cartridge selected.[/]")
            return

        table = Table(title=f"Module options ({self.current_cartridge_name})")
        table.add_column("Name", style="cyan")
        table.add_column("Current Setting", style="green")
        table.add_column("Description", style="white")

        for opt, val in self.cartridge_options.items():
            table.add_row(opt, str(val), "")

        self.rich_console.print(table)

    def show_commands(self, topic: Optional[str] = None) -> None:
        current_context = self.context_stack[-1]

        # 0. Builder Context Help
        if self.builder_stack:
            active = self.builder_stack[-1].entity_name
            table = Table(title=f"Builder Menu ({active})")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row("set <key> <val>", "Set property value")
            table.add_row("show", "Show current properties")
            table.add_row("save", "Commit and create entity")
            if active == "device":
                table.add_row("add peripheral <type>", "Add a nested peripheral")
            if active in ["service", "peripheral", "device"]:
                table.add_row("add vulnerability", "Add a finding")
            table.add_row("back", "Discard and return")
            self.rich_console.print(table)
            return

        # 1. Backend Context Help
        if current_context == "backend":
            table = Table(title="Backend Menu Commands")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row("list", "Show active backend connections")
            table.add_row("available", "List supported backend types")
            table.add_row("setup <type>", "Configure a new backend interface")
            table.add_row("back", "Return to main menu")
            self.rich_console.print(table)
            return

        # 2. Operation Context Help
        if current_context == "operation":
            table = Table(title="Operation Menu Commands")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            table.add_row(
                "set <key> <val>", "Set operation properties (name, ticket, etc)"
            )
            table.add_row("save", "Save operation to backend")
            table.add_row("load <name>", "Load operation from backend")
            table.add_row("delete <name>", "Delete operation from backend")
            table.add_row("back", "Return to main menu")
            self.rich_console.print(table)
            return

        # 3. Global Help (Root)
        if topic:
            topic = topic.lower()
            if topic == "ai":
                table = Table(title="AI Commands")
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
                table.add_row("awsaccount", "add awsaccount <name> <id>")
                self.rich_console.print(table)
                return

        table = Table(title="Global Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_row("operation [create]", "Manage operations (enter menu or create)")
        table.add_row("status", "Show visual status tree of current operation")
        table.add_row("add <type>", "Add objects to workspace (try 'help add')")
        table.add_row("use <cartridge>", "Select a module to use")
        table.add_row("ai <cmd>", "AI management and chat (try 'help ai')")
        table.add_row("backend", "Enter backend management menu")
        table.add_row("tools <cmd>", "AI tool management (try 'help tools')")
        table.add_row("back", "Exit current context")
        table.add_row("exit", "Terminate the console")

        if self.current_cartridge_instance:
            m_table = Table(title=f"Cartridge Commands ({self.current_cartridge_name})")
            m_table.add_column("Command", style="yellow")
            m_table.add_column("Description", style="white")
            for name, obj in inspect.getmembers(
                self.current_cartridge_instance, predicate=inspect.ismethod
            ):
                if name.startswith("do_"):
                    m_table.add_row(name[3:], obj.__doc__ or "No description")
            self.rich_console.print(m_table)

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

    async def cmd_backend_setup(self, *args: str) -> None:
        """Setup a specific backend."""
        if len(args) < 1:
            self.rich_console.print("Usage: setup <type>")
            return

        itype = args[0].lower()

        if itype == "bugzilla":
            url = await self.session.prompt_async(
                "Bugzilla URL (e.g. https://bz.example.com): "
            )
            api_key = await self.session.prompt_async("API Key: ", is_password=True)
            if url and api_key:
                backend = BugzillaBackend(base_url=url, api_key=api_key)
                Ticket.register_backend("bugzilla", backend, make_default=True)
                self.rich_console.print(
                    f"[bold green]✔[/] Interface established: Bugzilla @ {url}"
                )

        elif itype == "json_storage":
            path = await self.session.prompt_async(
                "Storage directory (default: .wintermute_data): "
            )
            path = path or ".wintermute_data"
            backend_s = JsonFileBackend(base_path=path)
            Operation.register_backend("json_storage", backend_s, make_default=True)
            self.operation.save()
            self.rich_console.print(f"[bold green]✔[/] Persistence layer ready: {path}")

        elif itype == "docx_report":
            tpl_dir = await self.session.prompt_async(
                "Templates directory (default: templates): "
            )
            tpl_dir = tpl_dir or "templates"
            backend_r = DocxTplPerVulnBackend(
                template_dir=tpl_dir,
                main_template="report_main.docx",
                vuln_template="report_vuln.docx",
            )
            Report.register_backend("word_tpl", backend_r, make_default=True)
            self.rich_console.print(
                f"[bold green]✔[/] Reporting module loaded: {tpl_dir}"
            )

        else:
            self.rich_console.print(f"[red][!] neural interface '{itype}' unknown.[/]")

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

        elif cmd == "edit" and len(args) >= 2:
            self.cmd_edit_enter(args[0], args[1])
            return True

        elif cmd == "use" and args:
            self.cmd_use(args[0])
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
                                    f"[*] Entering {p_type} builder..."
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
                                "[*] Entering vulnerability builder..."
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

                if not handled:
                    if cmd:
                        self.rich_console.print(f"[red][!] Unknown command: {cmd}[/]")

                else:
                    self.rich_console.print(
                        f"[red]Unknown context: {current_context}[/]"
                    )

            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            except Exception as e:
                self.rich_console.print(f"[red][!] Console Error: {e}[/]")
                logger.exception("REPL Error")

        self.rich_console.print("[bold red]Shutting down Wintermute Console...[/]")


def main() -> None:
    console = WintermuteConsole()
    asyncio.run(console.run())


if __name__ == "__main__":
    main()
