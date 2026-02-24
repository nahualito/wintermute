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

from wintermute.ai.bootstrap import init_router
from wintermute.ai.provider import Router, llms
from wintermute.ai.tools_runtime import ToolsRuntime
from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.use import tool_calling_chat
from wintermute.ai.utils.tool_factory import register_tools
from wintermute.backends.bugzilla import BugzillaBackend
from wintermute.backends.docx_reports import DocxTplPerVulnBackend
from wintermute.backends.json_storage import JsonFileBackend
from wintermute.core import Operation
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


class WintermuteConsole:
    def __init__(self) -> None:
        self.rich_console = Console()
        self.session: PromptSession[Any] = PromptSession(history=InMemoryHistory())
        self.operation = Operation(operation_name="default")
        self.tools_runtime = ToolsRuntime()

        # Local context (Cartridge)
        self.current_cartridge_name: Optional[str] = None
        self.current_cartridge_instance: Optional[Any] = None
        self.cartridge_options: Dict[str, Any] = {}

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
        if self.current_cartridge_name:
            tokens.append(("class:context", f"exploit({self.current_cartridge_name})"))
        tokens.append(("class:prompt", " > "))
        return tokens

    def __pt_formatted_text__(self) -> Any:
        return self.get_prompt_tokens()

    def update_completer(self) -> NestedCompleter:
        """Builds and updates the nested completer based on current state."""

        # Gather dynamic completion data
        available_models: List[str] = []
        if self.ai_router:
            provider = llms.get(self.ai_router.default_provider)
            available_models = [m.name for m in provider.list_models()]

        catalog = self._scan_backends()
        backend_setup_options = {name: None for name in catalog.keys()}

        base_commands: Dict[str, Any] = {
            "operation": {
                "create": None,
            },
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
            "setg": {
                "bugzilla": None,
                "json_storage": None,
            },
            "use": {c: None for c in self.available_cartridges},
            "show": {
                "options": None,
                "commands": None,
                "cartridges": None,
                "info": None,
                "status": None,
            },
            "help": None,
            "ai": {
                "model": {
                    "set": {m: None for m in available_models},
                    "list": None,
                },
                "chat": None,  # renamed from original 'ai <prompt>' to 'ai chat <prompt>' or keeping original as well
            },
            "backend": {
                "setup": backend_setup_options,
                "list": None,
                "available": None,
            },
            "tools": {
                "load": None,
                "list": None,
            },
            "exit": None,
            "back": None,
        }

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

    # --- Global Commands ---

    def cmd_operation_create(self, name: str) -> None:
        self.operation = Operation(operation_name=name)
        self.rich_console.print(
            f"[*] Created new operation context: [bold cyan]{name}[/]"
        )

    def cmd_workspace_switch(self, name: str) -> None:
        self.operation.operation_name = name
        if self.operation.load():
            self.rich_console.print(
                f"[*] Switched to workspace: [bold cyan]{name}[/] (Loaded existing data)"
            )
        else:
            self.rich_console.print(
                f"[*] Switched to workspace: [bold cyan]{name}[/] (New context)"
            )

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

    def cmd_setg(self, backend_type: str, path: str, api_key: str = "") -> None:
        if backend_type == "json_storage":
            s_backend = JsonFileBackend(base_path=path)
            Operation.register_backend(backend_type, s_backend, make_default=True)
            self.operation.save()
            self.rich_console.print(
                f"[*] Registered Storage backend: {backend_type} at {path}"
            )
        elif backend_type == "bugzilla":
            if not api_key:
                self.rich_console.print(
                    "[red][!] Bugzilla requires an api_key: setg bugzilla <url> <api_key>[/]"
                )
                return
            t_backend = BugzillaBackend(base_url=path, api_key=api_key)
            Ticket.register_backend("bugzilla", t_backend, make_default=True)
            self.rich_console.print(
                f"[*] Registered Ticket backend: {backend_type} at {path}"
            )
        else:
            self.rich_console.print(
                f"[red][!] Unknown or unsupported backend type for setg: {backend_type}[/]"
            )

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

    def cmd_back(self) -> None:
        self.current_cartridge_name = None
        self.current_cartridge_instance = None
        self.cartridge_options = {}

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
                table.add_row("chat", "ai chat <prompt>", "Send a message to the AI")
                table.add_row("(default)", "ai <prompt>", "Alias for 'ai chat'")
                self.rich_console.print(table)
                return
            elif topic == "backend":
                table = Table(title="Backend Management Commands")
                table.add_column("Sub-command", style="cyan")
                table.add_column("Usage", style="magenta")
                table.add_column("Description", style="white")
                table.add_row("list", "backend list", "Show active connections")
                table.add_row(
                    "available", "backend available", "List supported backend types"
                )
                table.add_row(
                    "setup", "backend setup <type>", "Interactive configuration wizard"
                )
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
        table.add_row("operation create <name>", "Create a new operation workspace")
        table.add_row("workspace switch <name>", "Switch to a workspace")
        table.add_row("add <type>", "Add objects to workspace (try 'help add')")
        table.add_row("setg <backend> <path>", "Set global storage backend")
        table.add_row("use <cartridge>", "Select a module to use")
        table.add_row("ai <cmd>", "AI management and chat (try 'help ai')")
        table.add_row("backend <cmd>", "Backend & persistence (try 'help backend')")
        table.add_row("tools <cmd>", "AI tool management (try 'help tools')")
        table.add_row("back", "Exit current cartridge context")
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

        elif sub == "chat" or (sub not in ["model"]):
            # Default to chat if not 'model'
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

    async def cmd_backend(self, *args: str) -> None:
        if not args:
            self.rich_console.print("Usage: backend <list|available|setup> [args]")
            return

        sub = args[0].lower()
        if sub == "list":
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

        elif sub == "available":
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
                "[dim]Use 'backend setup <name>' to initialize an interface.[/]"
            )

        elif sub == "setup" and len(args) >= 2:
            itype = args[1].lower()

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
                self.rich_console.print(
                    f"[bold green]✔[/] Persistence layer ready: {path}"
                )

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
                self.rich_console.print(
                    f"[red][!] neural interface '{itype}' unknown.[/]"
                )
        else:
            self.rich_console.print("Usage: backend setup <type>")

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

                if cmd == "exit":
                    break

                # Global Command Dispatch
                if cmd == "operation" and args and args[0] == "create":
                    self.cmd_operation_create(args[1] if len(args) > 1 else "default")
                elif cmd == "workspace" and args and args[0] == "switch":
                    self.cmd_workspace_switch(args[1] if len(args) > 1 else "default")
                elif cmd == "add":
                    if not args:
                        continue
                    sub = args[0]
                    if sub == "analyst" and len(args) >= 4:
                        self.cmd_add_analyst(args[1], args[2], args[3])
                    elif sub == "device" and len(args) >= 2:
                        self.cmd_add_device(
                            args[1], args[2] if len(args) > 2 else "127.0.0.1"
                        )
                    elif sub == "user" and len(args) >= 4:
                        self.cmd_add_user(args[1], args[2], args[3])
                    elif sub == "service" and len(args) >= 4:
                        self.cmd_add_service(args[1], args[2], args[3])
                    elif sub == "awsaccount" and len(args) >= 3:
                        self.cmd_add_awsaccount(args[1], args[2])
                elif cmd == "setg" and len(args) >= 2:
                    self.cmd_setg(args[0], args[1], args[2] if len(args) > 2 else "")
                elif cmd == "use" and args:
                    self.cmd_use(args[0])
                elif cmd == "set" and len(args) >= 2:
                    self.cmd_set(args[0], args[1])
                elif cmd == "run":
                    self.cmd_run()
                elif cmd == "back":
                    self.cmd_back()
                elif cmd == "show":
                    if args and args[0] == "options":
                        self.show_options()
                    elif args and args[0] == "commands":
                        self.show_commands()
                    elif args and args[0] == "cartridges":
                        self.rich_console.print(
                            f"Available Cartridges: {', '.join(self.available_cartridges)}"
                        )
                elif cmd == "help":
                    self.show_commands(args[0] if args else None)
                elif cmd == "ai" and args:
                    await self.cmd_ai(*args)
                elif cmd == "integration" and args:
                    await self.cmd_backend(*args)
                elif cmd == "backend" and args:
                    await self.cmd_backend(*args)
                elif cmd == "tools" and args:
                    self.cmd_tools(*args)

                # Dynamic Cartridge Commands
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
                        self.rich_console.print(
                            f"[red][!] Cartridge command error: {e}[/]"
                        )

                else:
                    if cmd:
                        self.rich_console.print(f"[red][!] Unknown command: {cmd}[/]")

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
