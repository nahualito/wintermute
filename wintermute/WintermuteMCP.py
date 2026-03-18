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

"""Wintermute MCP Server — Stateful Translation Layer for LLM Agents.

This MCP server exposes the full Wintermute hardware-security and pentesting
library to autonomous LLM agents via the Model Context Protocol.

Architecture
------------
Because LLM agents cannot hold Python memory references, this server maintains
an internal **ObjectRegistry** that maps human-readable string IDs to live
Python objects.  Every creation tool returns a string ID; every action tool
accepts one.  The LLM never sees raw memory addresses — only stable, meaningful
identifiers like ``"op:acme-pentest"`` or ``"dev:iot-camera"``.

Registry Flow
~~~~~~~~~~~~~
1. Agent calls ``create_operation(name="acme-pentest")``
2. Server instantiates ``Operation("acme-pentest")``, stores it under
   ``"op:acme-pentest"`` in the registry, and returns the ID string.
3. Agent calls ``add_device(operation_id="op:acme-pentest", hostname="gw01")``
4. Server looks up ``"op:acme-pentest"`` → ``Operation`` object, calls
   ``op.addDevice("gw01")``, stores the new ``Device`` as ``"dev:gw01"``,
   and returns that ID.
5. Agent can later call ``get_device_info(device_id="dev:gw01")`` to inspect
   the object, or ``addVulnerability_Device(device_id="dev:gw01", ...)`` to
   mutate it.

Running
-------
    wintermute-mcp                         # SSE on 127.0.0.1:31337
    wintermute-mcp --host 0.0.0.0 --port 9000
    wintermute-mcp --transport stdio       # for pipe-based MCP clients
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Wintermute domain imports
# ---------------------------------------------------------------------------
from wintermute.ai.bootstrap import init_router
from wintermute.ai.provider import Router, llms
from wintermute.ai.tools_runtime import tools as global_tool_registry
from wintermute.ai.use import simple_chat
from wintermute.backends.json_storage import JsonFileBackend
from wintermute.cloud.aws import AWSAccount, AWSServiceType
from wintermute.core import (
    Operation,
    RunStatus,
    TestCase,
    TestCaseRun,
    TestPlan,
)
from wintermute.findings import ReproductionStep, Vulnerability
from wintermute.hardware import Architecture, Processor
from wintermute.peripherals import JTAG, UART
from wintermute.reports import Report, ReportSpec
from wintermute.tickets import InMemoryBackend, Status, Ticket
from wintermute.utils.findings import (
    add_reproduction_step,
    add_vulnerability,
    get_vulnerability,
    remove_vulnerability,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Server instance — tools are registered via decorators below.
# ---------------------------------------------------------------------------
mcp = FastMCP("WintermuteMCP")


# ═══════════════════════════════════════════════════════════════════════════
#  OBJECT REGISTRY — Stateful Translation Layer
# ═══════════════════════════════════════════════════════════════════════════
# The registry maps deterministic string IDs to live Python objects so that
# LLM agents can reference them across tool calls without holding pointers.
# IDs follow the convention  ``<type>:<hint>``  where *hint* derives from a
# natural key (hostname, uid, operation_name …).  A collision counter is
# appended when needed  (``dev:gw01``, ``dev:gw01:2``).


class ObjectRegistry:
    """In-process object store keyed by agent-friendly string IDs."""

    def __init__(self) -> None:
        self._objects: dict[str, Any] = {}
        self._types: dict[str, str] = {}  # id → human type label
        self._counters: dict[str, int] = {}

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _sanitize(hint: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", hint)[:48]

    def _make_id(self, prefix: str, hint: str) -> str:
        base = f"{prefix}:{self._sanitize(hint)}"
        if base not in self._objects:
            return base
        self._counters.setdefault(base, 1)
        self._counters[base] += 1
        return f"{base}:{self._counters[base]}"

    # -- public API -------------------------------------------------------

    def store(self, obj: Any, type_label: str, hint: str, *, prefix: str = "") -> str:
        """Persist *obj* and return a unique string ID for the LLM."""
        pfx = prefix or type_label
        oid = self._make_id(pfx, hint)
        self._objects[oid] = obj
        self._types[oid] = type_label
        return oid

    def get(self, oid: str) -> Any | None:
        """Retrieve the Python object behind *oid*, or ``None``."""
        return self._objects.get(oid)

    def get_typed(self, oid: str, expected: type[Any]) -> Any | None:
        """Return the object only if it is an instance of *expected*."""
        obj = self._objects.get(oid)
        if obj is not None and isinstance(obj, expected):
            return obj
        return None

    def delete(self, oid: str) -> bool:
        if oid in self._objects:
            del self._objects[oid]
            del self._types[oid]
            return True
        return False

    def list_all(self) -> dict[str, str]:
        """Return ``{id: type_label}`` for every registered object."""
        return dict(self._types)


# Global singletons
registry = ObjectRegistry()
_ai_router: Router | None = None


def _router() -> Router | None:
    """Lazy-init helper so we don't crash at import when keys are absent."""
    global _ai_router  # noqa: PLW0603
    return _ai_router


def _require(oid: str, expected: type[Any], label: str) -> Any:
    """Look up *oid* in the registry; return a structured error string on failure."""
    obj = registry.get_typed(oid, expected)
    if obj is None:
        present = registry.get(oid)
        if present is None:
            raise ValueError(
                f"ID '{oid}' not found in registry. "
                f"Call list_active_objects() to see valid IDs."
            )
        raise TypeError(f"ID '{oid}' is a {type(present).__name__}, not a {label}.")
    return obj


def _ser(obj: Any) -> str:
    """Serialize a BaseModel (or dict / list) to indented JSON text."""
    if hasattr(obj, "to_dict"):
        return json.dumps(obj.to_dict(), indent=2, default=str)
    return json.dumps(obj, indent=2, default=str)


# ═══════════════════════════════════════════════════════════════════════════
#  A.  REGISTRY INTROSPECTION
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def list_active_objects() -> str:
    """Return every object currently held in the Wintermute session registry.

    Call this tool FIRST in any new session to discover which string IDs are
    already available.  The response is a JSON object mapping each string ID
    to its type label (e.g. ``"op:acme" → "operation"``).

    Returns:
        JSON mapping ``{string_id: type_label}``.
    """
    data = registry.list_all()
    if not data:
        return "Registry is empty. Use create_operation() to begin."
    return json.dumps(data, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
#  B.  CORE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def create_operation(
    name: str,
    ticket: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> str:
    """Create a new top-level Wintermute Operation and register it.

    An Operation is the root container for an entire engagement — all devices,
    users, cloud accounts, test plans, and findings live beneath it.  You MUST
    create an Operation before adding any other objects.

    Args:
        name: A short, unique identifier for the engagement (e.g.
              ``"acme-iot-audit-2025"``).
        ticket: Optional ticket or tracking reference.
        start_date: Engagement start in MM/DD/YYYY format (defaults to today).
        end_date: Engagement end in MM/DD/YYYY format (defaults to today).

    Returns:
        The string ID assigned to this Operation (e.g. ``"op:acme-iot-audit-2025"``).
        Use this ID in all subsequent calls that require an ``operation_id``.
    """
    kwargs: dict[str, Any] = {"operation_name": name}
    if ticket:
        kwargs["ticket"] = ticket
    if start_date:
        kwargs["start_date"] = start_date
    if end_date:
        kwargs["end_date"] = end_date
    op = Operation(**kwargs)
    oid = registry.store(op, "operation", name, prefix="op")
    return f"Created Operation. ID: {oid}"


@mcp.tool()
async def edit_operation(
    operation_id: str,
    ticket: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> str:
    """Modify mutable fields on an existing Operation.

    You MUST supply a valid ``operation_id`` obtained from create_operation().

    Args:
        operation_id: The registry string ID of the target Operation.
        ticket: New ticket reference (leave empty to keep current value).
        start_date: New start date in MM/DD/YYYY (leave empty to keep current).
        end_date: New end date in MM/DD/YYYY (leave empty to keep current).

    Returns:
        Confirmation message with the updated fields.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    changed: list[str] = []
    if ticket:
        op.ticket = ticket
        changed.append("ticket")
    if start_date:
        op.start_date = start_date
        changed.append("start_date")
    if end_date:
        op.end_date = end_date
        changed.append("end_date")
    if not changed:
        return "No fields provided — nothing changed."
    return f"Updated {operation_id}: {', '.join(changed)}"


@mcp.tool()
async def delete_operation(operation_id: str) -> str:
    """Remove an Operation and all its child references from the registry.

    WARNING: This deletes the in-memory Operation object. Any devices, users,
    or cloud accounts that were registered from this Operation will become
    orphaned in the registry.  Call list_active_objects() afterward to clean up.

    Args:
        operation_id: The registry string ID of the Operation to delete.

    Returns:
        Confirmation or error message.
    """
    if registry.delete(operation_id):
        return f"Deleted {operation_id} from registry."
    return f"ID '{operation_id}' not found."


@mcp.tool()
async def get_operation_info(operation_id: str) -> str:
    """Retrieve the full serialized state of an Operation.

    Use this tool to inspect all devices, users, cloud accounts, test plans,
    test runs, and analysts that belong to an Operation.  The response is a
    JSON document produced by ``Operation.to_dict()``.

    Args:
        operation_id: The registry string ID of the target Operation.

    Returns:
        Full JSON representation of the Operation.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    return _ser(op)


# ═══════════════════════════════════════════════════════════════════════════
#  C.  MANAGEMENT BACKENDS
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def configure_ai_router() -> str:
    """Initialize the Wintermute AI router and register all LLM providers.

    This bootstraps Bedrock, Groq, OpenAI, and HuggingFace providers using
    environment variables (``AWS_REGION``, ``GROQ_API_KEY``, ``OPENAI_API_KEY``,
    ``BEDROCK_MODEL_ID``).  It also scans ``./knowledge_bases/`` for RAG
    indices and registers them as ``rag-<name>`` providers.

    Run this tool ONCE at the start of any session that requires AI features
    (enrichment, chat, tool calling).

    Returns:
        List of registered providers and the default provider name.
    """
    global _ai_router  # noqa: PLW0603
    try:
        _ai_router = init_router()
        return json.dumps(
            {
                "status": "ok",
                "default_provider": _ai_router.default_provider,
                "available_providers": llms.get_provider_descriptions(),
            },
            indent=2,
        )
    except Exception as e:
        return f"Router init failed: {e}"


@mcp.tool()
async def set_ai_default_provider(
    provider: str | None = None,
    model: str | None = None,
) -> str:
    """Switch the AI router to a different LLM provider or model.

    You MUST have called configure_ai_router() first.  Use this to toggle
    between base providers (``"bedrock"``) and RAG-augmented providers
    (``"rag-tiny_hardware_test"``).  Setting ``provider`` to a RAG name makes
    all subsequent AI queries context-aware.

    Args:
        provider: Provider name from the registry (e.g. ``"bedrock"``,
                  ``"groq"``, ``"rag-my_kb"``).  Empty string keeps current.
        model: Model ID override.  Empty string keeps current.

    Returns:
        Confirmation of the new default settings.
    """
    router = _router()
    if router is None:
        return "AI router not initialized. Call configure_ai_router() first."
    if not provider and not model:
        return "Provide at least one of 'provider' or 'model'."
    router.set_default(
        provider=provider if provider else None,
        model=model if model else None,
    )
    return f"AI default updated: provider={router.default_provider}, model={router.default_model}"


@mcp.tool()
async def setup_storage_backend(
    backend_type: str | None = None,
    base_path: str | None = None,
    table_name: str | None = None,
    region: str | None = None,
) -> str:
    """Register a persistence backend for Operation save/load.

    Supported backend types:
    - ``"json"`` — Local JSON flat-file storage (default).
    - ``"dynamodb"`` — AWS DynamoDB cloud storage (requires AWS credentials).

    After calling this, use ``save_operation()`` and ``load_operation()`` to
    persist and restore Operations.

    Args:
        backend_type: ``"json"`` or ``"dynamodb"``.
        base_path: Directory for JSON files (only used with ``"json"``).
        table_name: DynamoDB table name (only used with ``"dynamodb"``).
        region: AWS region (only used with ``"dynamodb"``).

    Returns:
        Confirmation with the backend name.
    """
    backend_type = backend_type or "json"
    base_path = base_path or ".wintermute_data"
    table_name = table_name or "WintermuteOperations"
    region = region or "us-east-1"
    if backend_type == "json":
        backend = JsonFileBackend(base_path=base_path)
        Operation.register_backend("json", backend, make_default=True)
        return f"Registered JsonFileBackend at '{base_path}' as default."
    elif backend_type == "dynamodb":
        from wintermute.backends.dynamodb import DynamoDBBackend

        backend_ddb = DynamoDBBackend(
            table_name=table_name, region_name=region, create_if_missing=True
        )
        Operation.register_backend("dynamodb", backend_ddb, make_default=True)
        return f"Registered DynamoDBBackend (table={table_name}, region={region}) as default."
    return f"Unknown backend type: '{backend_type}'. Use 'json' or 'dynamodb'."


@mcp.tool()
async def save_operation(operation_id: str) -> str:
    """Persist an Operation to the currently registered storage backend.

    You MUST call setup_storage_backend() first.  The Operation is saved using
    its ``operation_name`` as the storage key.

    Args:
        operation_id: The registry string ID of the Operation to save.

    Returns:
        Confirmation or error message.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    try:
        result = op.save()
        return f"Saved '{op.operation_name}': {result}"
    except Exception as e:
        return f"Save failed: {e}"


@mcp.tool()
async def load_operation(operation_name: str) -> str:
    """Load a previously saved Operation from the storage backend.

    Creates a new Operation shell, hydrates it from storage, and registers it
    in the session registry.  Also registers all child objects (devices, users,
    cloud accounts) so they are immediately addressable.

    Args:
        operation_name: The ``operation_name`` key used when the Operation was
                        saved (NOT a registry ID — this is the raw name).

    Returns:
        The registry string ID for the loaded Operation, or an error.
    """
    try:
        op = Operation(operation_name=operation_name)
        op.load()
    except Exception as e:
        return f"Load failed: {e}"
    oid = registry.store(op, "operation", operation_name, prefix="op")
    # Auto-register children
    for dev in op.devices:
        registry.store(dev, "device", dev.hostname, prefix="dev")
    for user in op.users:
        registry.store(user, "user", user.uid, prefix="user")
    for acc in op.cloud_accounts:
        hint = getattr(acc, "account_id", None) or getattr(acc, "name", "cloud")
        pref = "aws" if isinstance(acc, AWSAccount) else "cloud"
        registry.store(acc, type(acc).__name__, str(hint), prefix=pref)
    return f"Loaded and registered as {oid} with {len(op.devices)} devices, {len(op.users)} users, {len(op.cloud_accounts)} cloud accounts."


@mcp.tool()
async def setup_ticket_backend(
    backend_type: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    default_product: str | None = None,
    default_component: str | None = None,
) -> str:
    """Register a ticketing backend for vulnerability and incident tracking.

    Supported backend types:
    - ``"memory"`` — In-memory store (useful for testing / ephemeral sessions).
    - ``"bugzilla"`` — Bugzilla REST API (requires ``base_url`` and ``api_key``).

    After calling this, use ``create_ticket()``, ``read_ticket()``,
    ``update_ticket()`` to manage tickets.

    Args:
        backend_type: ``"memory"`` or ``"bugzilla"``.
        base_url: Bugzilla REST endpoint (e.g. ``"http://host/bugzilla/rest"``).
        api_key: Bugzilla API key.
        default_product: Default Bugzilla product for new tickets.
        default_component: Default Bugzilla component for new tickets.

    Returns:
        Confirmation with the backend name.
    """
    backend_type = backend_type or "memory"
    if backend_type == "memory":
        Ticket.register_backend("memory", InMemoryBackend(), make_default=True)
        return "Registered InMemoryBackend as default ticket backend."
    elif backend_type == "bugzilla":
        if not base_url or not api_key:
            return "Bugzilla backend requires 'base_url' and 'api_key'."
        from wintermute.backends.bugzilla import BugzillaBackend

        bz = BugzillaBackend(
            base_url=base_url,
            api_key=api_key,
            default_product=default_product or None,
            default_component=default_component or None,
        )
        Ticket.register_backend("bugzilla", bz, make_default=True)
        return f"Registered BugzillaBackend at '{base_url}' as default."
    return f"Unknown backend type: '{backend_type}'. Use 'memory' or 'bugzilla'."


@mcp.tool()
async def create_ticket(
    title: str,
    description: str | None = None,
    assignee: str | None = None,
    requester: str | None = None,
) -> str:
    """Create a new ticket in the configured ticketing backend.

    You MUST call setup_ticket_backend() first.

    Args:
        title: Short summary of the issue.
        description: Detailed description or reproduction notes.
        assignee: Person assigned to the ticket.
        requester: Person who requested the ticket.

    Returns:
        The ticket ID string assigned by the backend.
    """
    try:
        kwargs: dict[str, Any] = {"title": title, "description": description or ""}
        if assignee:
            kwargs["assignee"] = assignee
        if requester:
            kwargs["requester"] = requester
        tid: str = Ticket.create(**kwargs)
        return f"Ticket created: {tid}"
    except Exception as e:
        return f"Failed: {e}"


@mcp.tool()
async def read_ticket(ticket_id: str) -> str:
    """Read the current state of a ticket from the ticketing backend.

    Args:
        ticket_id: The ticket ID returned by create_ticket().

    Returns:
        JSON representation of the ticket data and comments.
    """
    try:
        t = Ticket.read(ticket_id)
        return _ser(t)
    except Exception as e:
        return f"Failed: {e}"


@mcp.tool()
async def update_ticket(
    ticket_id: str,
    status: str | None = None,
    assignee: str | None = None,
    description: str | None = None,
) -> str:
    """Update fields on an existing ticket.

    Args:
        ticket_id: The ticket ID to update.
        status: New status — one of ``"open"``, ``"in_progress"``,
                ``"resolved"``, ``"closed"`` (empty to skip).
        assignee: New assignee (empty to skip).
        description: Append a note / new description (empty to skip).

    Returns:
        Confirmation or error message.
    """
    try:
        fields: dict[str, Any] = {}
        if status:
            fields["status"] = Status(status)
        if assignee:
            fields["assignee"] = assignee
        if description:
            fields["description"] = description
        Ticket.update(ticket_id, **fields)
        return f"Updated ticket {ticket_id}."
    except Exception as e:
        return f"Failed: {e}"


@mcp.tool()
async def setup_report_backend(
    template_dir: str | None = None,
    main_template: str | None = None,
    vuln_template: str | None = None,
    test_run_template: str | None = None,
) -> str:
    """Register a DOCX report backend for automated report generation.

    After calling this, use ``generate_report()`` to produce Word documents.

    Args:
        template_dir: Path to the directory containing .docx templates.
        main_template: Filename of the main report template.
        vuln_template: Filename of the per-vulnerability template.
        test_run_template: Filename of the per-test-run template.

    Returns:
        Confirmation message.
    """
    from wintermute.backends.docx_reports import DocxTplPerVulnBackend

    backend = DocxTplPerVulnBackend(
        template_dir=template_dir or "templates",
        main_template=main_template or "report_main.docx",
        vuln_template=vuln_template or "report_vuln.docx",
        test_run_template=test_run_template or "report_test_run.docx",
    )
    Report.register_backend("docx", backend, make_default=True)
    return f"Registered DocxTplPerVulnBackend from '{template_dir}' as default."


@mcp.tool()
async def generate_report(
    operation_id: str,
    title: str | None = None,
    output_path: str | None = None,
    author: str | None = None,
    summary: str | None = None,
) -> str:
    """Generate a DOCX report from an Operation's findings.

    You MUST call setup_report_backend() first.  The report collects all
    vulnerabilities found across the Operation's devices, services, and cloud
    accounts and renders them using the configured templates.

    Args:
        operation_id: Registry ID of the source Operation.
        title: Report title (appears on the cover page).
        output_path: Filesystem path where the .docx file will be saved.
        author: Report author name.
        summary: Executive summary paragraph.

    Returns:
        Confirmation with the output path.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    title = title or "Pentest Report"
    output_path = output_path or "report_output.docx"
    spec = ReportSpec(title=title, author=author or None, summary=summary or "")
    try:
        Report.save(spec, [op], output_path)
        return f"Report saved to '{output_path}'."
    except Exception as e:
        return f"Report generation failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════
#  D.  DEVICE & SERVICE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def add_device(
    operation_id: str,
    hostname: str,
    ipaddr: str | None = None,
    macaddr: str | None = None,
    operating_system: str | None = None,
    fqdn: str | None = None,
) -> str:
    """Add a network device or embedded target to an Operation.

    You MUST provide a valid ``operation_id`` obtained from create_operation().
    The device is stored in the Operation's device list AND registered
    separately in the session registry so you can reference it by its own ID.

    Args:
        operation_id: Registry ID of the parent Operation.
        hostname: Unique hostname for the device (e.g. ``"iot-camera-v2"``).
        ipaddr: IP address (IPv4 or IPv6 string). Defaults to ``"0.0.0.0"``.
        macaddr: MAC address (defaults to ``"00:00:00:00:00:00"``).
        operating_system: OS description (e.g. ``"Linux 5.10"``).
        fqdn: Fully-qualified domain name.

    Returns:
        The device's registry string ID (e.g. ``"dev:iot-camera-v2"``).
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    op.addDevice(
        hostname,
        ipaddr or "0.0.0.0",
        macaddr or "00:00:00:00:00:00",
        operating_system or "",
        fqdn or "",
    )
    dev = op.getDeviceByHostname(hostname)
    if dev is None:
        return f"addDevice returned success but device '{hostname}' not found."
    dev_id = registry.store(dev, "device", hostname, prefix="dev")
    return f"Device added. ID: {dev_id}"


@mcp.tool()
async def edit_device(
    device_id: str,
    operating_system: str | None = None,
    fqdn: str | None = None,
    macaddr: str | None = None,
) -> str:
    """Modify mutable fields on a registered Device.

    Args:
        device_id: Registry ID of the target Device.
        operating_system: New OS string (empty to skip).
        fqdn: New FQDN (empty to skip).
        macaddr: New MAC address (empty to skip).

    Returns:
        Confirmation with changed fields.
    """
    from wintermute.core import Device

    dev: Device = _require(device_id, Device, "Device")
    changed: list[str] = []
    if operating_system:
        dev.operatingsystem = operating_system
        changed.append("operatingsystem")
    if fqdn:
        dev.fqdn = fqdn
        changed.append("fqdn")
    if macaddr:
        dev.macaddr = macaddr
        changed.append("macaddr")
    if not changed:
        return "No fields provided."
    return f"Updated {device_id}: {', '.join(changed)}"


@mcp.tool()
async def delete_device(
    operation_id: str,
    hostname: str | None = None,
    device_id: str | None = None,
) -> str:
    """Remove a Device from an Operation and the registry.

    Provide at least one of ``hostname`` or ``device_id`` to identify
    the device.  If both are given, both are used.

    Args:
        operation_id: Registry ID of the parent Operation.
        hostname: Hostname of the device to remove.
        device_id: Registry ID of the device to un-register.

    Returns:
        Confirmation or error message.
    """
    if not hostname and not device_id:
        return "Provide at least one of 'hostname' or 'device_id'."
    op: Operation = _require(operation_id, Operation, "Operation")
    result_parts: list[str] = []
    if hostname:
        removed = op.delDevice(hostname)
        result_parts.append(f"Device '{hostname}' removed from operation: {removed}")
    if device_id:
        registry.delete(device_id)
        result_parts.append(f"Registry entry '{device_id}' deleted.")
    return " ".join(result_parts)


@mcp.tool()
async def add_service_to_device(
    device_id: str,
    port_number: int,
    app: str | None = None,
    protocol: str | None = None,
    banner: str | None = None,
    transport_layer: str | None = None,
) -> str:
    """Add a network service (open port) to a Device.

    You MUST provide a valid ``device_id`` obtained from add_device().

    Args:
        device_id: Registry ID of the target Device.
        port_number: TCP/UDP port number.
        app: Application name (e.g. ``"nginx"``, ``"openssh"``).
        protocol: Network protocol (default ``"ipv4"``).
        banner: Service banner string captured during scanning.
        transport_layer: Transport description (e.g. ``"HTTPS"``, ``"SSH"``).

    Returns:
        The service's registry string ID.
    """
    from wintermute.core import Device

    dev: Device = _require(device_id, Device, "Device")
    dev.addService(
        protocol=protocol or "ipv4",
        app=app or "",
        portNumber=port_number,
        banner=banner or "",
        transport_layer=transport_layer or "",
    )
    svc = dev.services[-1]
    svc_id = registry.store(
        svc, "service", f"{dev.hostname}:{port_number}", prefix="svc"
    )
    return f"Service added. ID: {svc_id}"


@mcp.tool()
async def add_peripheral_to_device(
    device_id: str,
    peripheral_type: str,
    name: str | None = None,
    device_path: str | None = None,
    pins_json: str | None = None,
    baudrate: int | None = None,
) -> str:
    """Attach a hardware debug peripheral (UART, JTAG, etc.) to a Device.

    Use this after identifying physical debug interfaces on an embedded target.

    Args:
        device_id: Registry ID of the target Device.
        peripheral_type: One of ``"UART"`` or ``"JTAG"``.  Other types can be
                         added via the Wintermute library directly.
        name: Human-readable label (e.g. ``"debug-uart"``).
        device_path: OS device path (e.g. ``"/dev/ttyUSB0"``).
        pins_json: JSON object mapping pin names to board locations
                   (e.g. ``'{"tx":"J3-1","rx":"J3-2","gnd":"J3-3"}'``).
        baudrate: Baud rate for UART peripherals (ignored for JTAG).

    Returns:
        The peripheral's registry string ID.
    """
    from wintermute.core import Device

    dev: Device = _require(device_id, Device, "Device")
    try:
        pins: dict[str, Any] = json.loads(pins_json or "{}")
    except json.JSONDecodeError:
        pins = {}

    ptype = peripheral_type.upper()
    label = name or f"{ptype.lower()}-{len(dev.peripherals)}"
    dpath = device_path or ""
    periph: UART | JTAG
    if ptype == "UART":
        periph = UART(
            device_path=dpath, name=label, pins=pins, baudrate=baudrate or 115200
        )
    elif ptype == "JTAG":
        periph = JTAG(device_path=dpath, name=label, pins=pins)
    else:
        return (
            f"Unsupported peripheral_type: '{peripheral_type}'. Use 'UART' or 'JTAG'."
        )

    dev.peripherals.append(periph)
    pid = registry.store(periph, "peripheral", label, prefix="periph")
    return f"Peripheral added. ID: {pid}"


# ═══════════════════════════════════════════════════════════════════════════
#  E.  USER & ANALYST MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def add_analyst(
    operation_id: str,
    name: str,
    userid: str,
    email: str | None = None,
) -> str:
    """Add a security analyst to an Operation.

    Analysts are the team members performing the engagement.

    Args:
        operation_id: Registry ID of the parent Operation.
        name: Full name of the analyst.
        userid: Short username / ID.
        email: Contact email.

    Returns:
        Confirmation message.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    op.addAnalyst(name, userid, email or "")
    return f"Analyst '{userid}' added to {operation_id}."


@mcp.tool()
async def delete_analyst(operation_id: str, userid: str) -> str:
    """Remove an analyst from an Operation by userid.

    Args:
        operation_id: Registry ID of the parent Operation.
        userid: The analyst's userid to remove.

    Returns:
        Confirmation or error message.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    result = op.delAnalyst(userid)
    return f"Analyst '{userid}' removed: {result}"


@mcp.tool()
async def add_user(
    operation_id: str,
    uid: str,
    name: str,
    email: str | None = None,
    teams_json: str | None = None,
    dept: str | None = None,
) -> str:
    """Add an organizational user (employee, contractor) to an Operation.

    Users represent people in the target organization whose access and
    permissions are under review.

    Args:
        operation_id: Registry ID of the parent Operation.
        uid: Unique user identifier (e.g. ``"jsmith"``).
        name: Full name (e.g. ``"John Smith"``).
        email: Email address.
        teams_json: JSON array of team names (e.g. ``'["red-team","infra"]'``).
        dept: Department name.

    Returns:
        The user's registry string ID.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    try:
        teams: list[str] = json.loads(teams_json or '["default"]')
    except json.JSONDecodeError:
        teams = ["default"]
    op.addUser(uid=uid, name=name, email=email or "", teams=teams, dept=dept or "")
    user = next((u for u in op.users if u.uid == uid), None)
    if user is None:
        return f"addUser returned success but user '{uid}' not found."
    uid_reg = registry.store(user, "user", uid, prefix="user")
    return f"User added. ID: {uid_reg}"


@mcp.tool()
async def delete_user(operation_id: str, uid: str, user_id: str | None = None) -> str:
    """Remove a user from an Operation.

    Args:
        operation_id: Registry ID of the parent Operation.
        uid: The user's uid field to delete from the Operation.
        user_id: Registry ID of the user to un-register (optional).

    Returns:
        Confirmation or error message.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    result = op.delUser(uid)
    if user_id:
        registry.delete(user_id)
    return f"User '{uid}' removed: {result}"


# ═══════════════════════════════════════════════════════════════════════════
#  F.  CLOUD ACCOUNT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def add_cloud_account(
    operation_id: str,
    name: str,
    cloud_type: str | None = None,
    description: str | None = None,
    account_id: str | None = None,
) -> str:
    """Add a generic cloud account to an Operation.

    For AWS-specific accounts with IAM users/roles, prefer add_aws_account().

    Args:
        operation_id: Registry ID of the parent Operation.
        name: Account display name.
        cloud_type: Provider type (e.g. ``"AWS"``, ``"GCP"``, ``"Azure"``).
        description: Free-text description.
        account_id: Cloud provider account ID.

    Returns:
        The cloud account's registry string ID.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    kwargs: dict[str, Any] = {
        "name": name,
        "cloud_type": cloud_type or "AWS",
        "description": description or "",
    }
    if account_id:
        kwargs["account_id"] = account_id
    op.addCloudAccount(**kwargs)
    acc = op.cloud_accounts[-1]
    acc_id = registry.store(acc, type(acc).__name__, name, prefix="cloud")
    return f"Cloud account added. ID: {acc_id}"


@mcp.tool()
async def add_aws_account(
    operation_id: str,
    name: str,
    account_id: str | None = None,
    description: str | None = None,
    default_region: str | None = None,
    partition: str | None = None,
) -> str:
    """Add an AWS account with IAM support to an Operation.

    This creates an AWSAccount object which supports IAM users, IAM roles,
    AWS services, and per-account vulnerabilities.

    Args:
        operation_id: Registry ID of the parent Operation.
        name: Account display name (e.g. ``"acme-prod"``).
        account_id: AWS 12-digit account ID (e.g. ``"123456789012"``).
        description: Free-text description.
        default_region: Default AWS region (e.g. ``"us-east-1"``).
        partition: AWS partition (default ``"aws"``).

    Returns:
        The AWS account's registry string ID.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    kwargs: dict[str, Any] = {"name": name, "description": description or ""}
    if account_id:
        kwargs["account_id"] = account_id
    if default_region:
        kwargs["default_region"] = default_region
    if partition and partition != "aws":
        kwargs["partition"] = partition
    op.addAWSAccount(**kwargs)
    aws = op.awsaccounts[-1]
    aws_id = registry.store(aws, "AWSAccount", name, prefix="aws")
    return f"AWS account added. ID: {aws_id}"


@mcp.tool()
async def edit_aws_account(
    aws_account_id: str,
    description: str | None = None,
    default_region: str | None = None,
) -> str:
    """Modify mutable fields on a registered AWS Account.

    Args:
        aws_account_id: Registry ID of the target AWSAccount.
        description: New description (empty to skip).
        default_region: New default region (empty to skip).

    Returns:
        Confirmation with changed fields.
    """
    acc: AWSAccount = _require(aws_account_id, AWSAccount, "AWSAccount")
    changed: list[str] = []
    if description:
        acc.description = description
        changed.append("description")
    if default_region:
        acc.default_region = default_region
        changed.append("default_region")
    if not changed:
        return "No fields provided."
    return f"Updated {aws_account_id}: {', '.join(changed)}"


@mcp.tool()
async def delete_cloud_account(
    operation_id: str,
    name: str,
    cloud_account_id: str | None = None,
) -> str:
    """Remove a cloud account from an Operation and the registry.

    Args:
        operation_id: Registry ID of the parent Operation.
        name: The ``name`` field of the cloud account to remove.
        cloud_account_id: Registry ID to un-register (optional).

    Returns:
        Confirmation or error message.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    result = op.delCloudAccount(name)
    if cloud_account_id:
        registry.delete(cloud_account_id)
    return f"Cloud account '{name}' removed: {result}"


@mcp.tool()
async def add_iam_user_to_aws(
    aws_account_id: str,
    username: str,
    arn: str | None = None,
    administrator: bool | None = None,
    policies_json: str | None = None,
) -> str:
    """Add an IAM user to a registered AWS Account.

    Args:
        aws_account_id: Registry ID of the target AWSAccount.
        username: IAM username.
        arn: IAM user ARN (optional).
        administrator: Whether this user has admin privileges.
        policies_json: JSON array of attached policy ARNs.

    Returns:
        Confirmation message.
    """
    acc: AWSAccount = _require(aws_account_id, AWSAccount, "AWSAccount")
    try:
        policies: list[str] = json.loads(policies_json or "[]")
    except json.JSONDecodeError:
        policies = []
    acc.addIAMUser(
        username=username,
        arn=arn or None,
        administrator=administrator if administrator is not None else False,
        attached_policies=policies,
    )
    return f"IAM user '{username}' added to {aws_account_id}."


@mcp.tool()
async def add_iam_role_to_aws(
    aws_account_id: str,
    role_name: str,
    arn: str | None = None,
    administrator: bool | None = None,
    policies_json: str | None = None,
) -> str:
    """Add an IAM role to a registered AWS Account.

    Args:
        aws_account_id: Registry ID of the target AWSAccount.
        role_name: IAM role name.
        arn: IAM role ARN (optional).
        administrator: Whether this role has admin privileges.
        policies_json: JSON array of attached policy ARNs.

    Returns:
        Confirmation message.
    """
    acc: AWSAccount = _require(aws_account_id, AWSAccount, "AWSAccount")
    try:
        policies: list[str] = json.loads(policies_json or "[]")
    except json.JSONDecodeError:
        policies = []
    acc.addIAMRole(
        role_name=role_name,
        arn=arn or None,
        administrator=administrator if administrator is not None else False,
        attached_policies=policies,
    )
    return f"IAM role '{role_name}' added to {aws_account_id}."


@mcp.tool()
async def add_service_to_aws(
    aws_account_id: str,
    name: str,
    arn: str | None = None,
    service_type: str | None = None,
    config_json: str | None = None,
) -> str:
    """Add an AWS service resource to a registered AWS Account.

    Args:
        aws_account_id: Registry ID of the target AWSAccount.
        name: Service display name.
        arn: Full ARN of the service resource (provide when known).
        service_type: AWS service type — one of ``ec2``, ``s3``, ``rds``,
                      ``lambda``, ``iam``, ``vpc``, ``dynamodb``, ``sqs``,
                      ``sns``, ``elb``, ``eks``, ``ssm``, ``ecr``, ``other``.
        config_json: JSON object with service-specific configuration.

    Returns:
        Confirmation message.
    """
    acc: AWSAccount = _require(aws_account_id, AWSAccount, "AWSAccount")
    try:
        stype = AWSServiceType((service_type or "other").lower())
    except ValueError:
        stype = AWSServiceType.OTHER
    try:
        config: dict[str, Any] = json.loads(config_json or "{}")
    except json.JSONDecodeError:
        config = {}
    acc.addService(name=name, arn=arn or "", service_type=stype, config=config)
    return f"AWS service '{name}' ({stype.value}) added to {aws_account_id}."


# ═══════════════════════════════════════════════════════════════════════════
#  G.  TESTING FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def add_test_plan(
    operation_id: str,
    code: str,
    name: str,
    description: str | None = None,
    test_cases_json: str | None = None,
) -> str:
    """Add a test plan to an Operation.

    A test plan groups related test cases.  Each test case defines a specific
    check to execute against a target (device, peripheral, cloud resource).

    Args:
        operation_id: Registry ID of the parent Operation.
        code: Unique plan code (e.g. ``"TP-UART-001"``).
        name: Human-readable plan name.
        description: What this plan covers.
        test_cases_json: JSON array of test case objects.  Each element must
                         have at least ``{"code": "...", "name": "..."}``.
                         Additional fields: ``description``, ``execution_mode``
                         (``"once"``, ``"per_device"``, ``"per_binding"``).

    Returns:
        The test plan's registry string ID.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    try:
        raw_cases: list[dict[str, Any]] = json.loads(test_cases_json or "[]")
    except json.JSONDecodeError:
        raw_cases = []
    cases = [TestCase(**tc) for tc in raw_cases] if raw_cases else None
    tp = TestPlan(code=code, name=name, description=description or "", test_cases=cases)
    op.addTestPlan(tp)
    tp_id = registry.store(tp, "test_plan", code, prefix="tp")
    return f"Test plan added. ID: {tp_id}"


@mcp.tool()
async def add_test_plan_from_json(
    operation_id: str,
    json_path: str,
) -> str:
    """Load a test plan from a JSON file and add it to an Operation.

    Wintermute ships test plans in the ``TestPlans/`` directory.  Pass the
    path to one of those JSON files.

    Args:
        operation_id: Registry ID of the parent Operation.
        json_path: Filesystem path to the test plan JSON file
                   (e.g. ``"TestPlans/TP-HW-BLACKBOX-001.json"``).

    Returns:
        The test plan's registry string ID, or an error if the file is invalid.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    try:
        with open(json_path, "r") as f:
            data: dict[str, Any] = json.load(f)
    except Exception as e:
        return f"Failed to read '{json_path}': {e}"
    tp = TestPlan.from_dict(data)
    op.addTestPlan(tp)
    tp_id = registry.store(tp, "test_plan", tp.code, prefix="tp")
    return f"Loaded test plan '{tp.name}' ({tp.code}). ID: {tp_id}"


@mcp.tool()
async def generate_test_runs(
    operation_id: str,
    replace: bool | None = None,
) -> str:
    """Generate test case runs from all test plans in an Operation.

    This expands every test case across its execution mode (once, per_device,
    per_binding) and creates ``TestCaseRun`` entries with status ``not_run``.

    Args:
        operation_id: Registry ID of the parent Operation.
        replace: If ``True``, clear existing runs before generating new ones.

    Returns:
        JSON list of generated run IDs and their test case codes.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    runs = op.generateTestRuns(replace=replace if replace is not None else False)
    result: list[dict[str, str]] = []
    for run in runs:
        rid = registry.store(run, "test_run", run.run_id[:8], prefix="run")
        result.append(
            {
                "registry_id": rid,
                "run_id": run.run_id,
                "test_case_code": run.test_case_code,
            }
        )
    return json.dumps(result, indent=2)


@mcp.tool()
async def update_test_run_status(
    test_run_id: str,
    status: str,
    executed_by: str | None = None,
    notes: str | None = None,
) -> str:
    """Update the execution status of a test case run.

    Valid statuses: ``not_run``, ``in_progress``, ``passed``, ``failed``,
    ``blocked``, ``not_applicable``.

    Setting status to ``in_progress`` also calls ``start()`` (sets
    ``started_at``).  Any terminal status calls ``finish()`` (sets
    ``ended_at``).

    Args:
        test_run_id: Registry ID of the TestCaseRun.
        status: New status string (see above).
        executed_by: Analyst userid who performed the test.
        notes: Free-text execution notes.

    Returns:
        Confirmation with the new status.
    """
    run: TestCaseRun = _require(test_run_id, TestCaseRun, "TestCaseRun")
    try:
        new_status = RunStatus(status)
    except ValueError:
        return f"Invalid status '{status}'. Valid: {[s.value for s in RunStatus]}"
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
    if executed_by:
        run.executed_by = executed_by
    if notes:
        run.notes = notes
    return f"Run {test_run_id} -> {new_status.value}"


@mcp.tool()
async def get_test_execution_status(operation_id: str) -> str:
    """Generate a status report of all test runs in an Operation.

    Returns aggregate counts by status (not_run, in_progress, passed, failed,
    blocked, not_applicable) for all test case runs.

    Args:
        operation_id: Registry ID of the parent Operation.

    Returns:
        JSON status report with ``total_runs`` and ``by_status`` breakdown.
    """
    op: Operation = _require(operation_id, Operation, "Operation")
    now = datetime.now(timezone.utc)
    report = op.statusReport(start=now - timedelta(days=365), end=now)
    return json.dumps(report, indent=2, default=str)


@mcp.tool()
async def add_reproduction_step_to_vulnerability(
    target_id: str,
    vuln_title: str,
    step_title: str,
    step_description: str | None = None,
    tool: str | None = None,
    action: str | None = None,
    confidence: int | None = None,
    arguments_json: str | None = None,
) -> str:
    """Attach a reproduction step to a specific vulnerability on any target.

    The ``target_id`` can be a Device, Service, AWSAccount, User, or
    Peripheral — any registry object that holds a ``vulnerabilities`` list.
    The vulnerability is looked up by ``vuln_title``.

    Args:
        target_id: Registry ID of the object holding the vulnerability.
        vuln_title: Exact title of the vulnerability to attach the step to.
        step_title: Short title for this reproduction step.
        step_description: Detailed description of what this step does.
        tool: Tool or binary used (e.g. ``"nmap"``, ``"openocd"``).
        action: Action performed by the tool (e.g. ``"scan"``, ``"read"``).
        confidence: Confidence score 0-100.
        arguments_json: JSON array of command-line arguments.

    Returns:
        Confirmation or error message.
    """
    obj = registry.get(target_id)
    if obj is None:
        return f"ID '{target_id}' not found."
    if not hasattr(obj, "vulnerabilities"):
        return f"Object '{target_id}' does not support vulnerabilities."
    try:
        args_list: list[str] = json.loads(arguments_json or "[]")
    except json.JSONDecodeError:
        args_list = []
    step = ReproductionStep(
        title=step_title,
        description=step_description or "",
        tool=tool or None,
        action=action or None,
        confidence=confidence if confidence is not None else 0,
        arguments=args_list,
    )
    result = add_reproduction_step(obj, title=vuln_title, step=step)
    return f"Step '{step_title}' added to vulnerability '{vuln_title}': {result}"


# ═══════════════════════════════════════════════════════════════════════════
#  H.  VULNERABILITY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


_DEFAULT_RISK_JSON = '{"likelihood":"Low","impact":"Low","severity":"Low"}'


def _add_vuln_to(
    obj: Any,
    title: str,
    description: str | None,
    threat: str | None,
    cvss: int | None,
    risk_json: str | None,
    verified: bool | None,
) -> str:
    """Internal helper — adds a Vulnerability via the utils helper."""
    rj = risk_json if risk_json is not None else _DEFAULT_RISK_JSON
    try:
        risk: dict[Any, Any] | None = json.loads(rj) if rj else None
    except json.JSONDecodeError:
        risk = None
    vuln = add_vulnerability(
        obj,
        title=title,
        description=description or "",
        threat=threat or "",
        cvss=cvss if cvss is not None else 0,
        risk=risk,
        verified=verified if verified is not None else False,
    )
    return (
        f"Vulnerability '{vuln.title}' (cvss={vuln.cvss}) added. vuln_id={vuln.vuln_id}"
    )


@mcp.tool()
async def addVulnerability_Device(
    device_id: str,
    title: str,
    description: str | None = None,
    threat: str | None = None,
    cvss: int | None = None,
    risk_json: str | None = None,
    verified: bool | None = None,
) -> str:
    """Add a vulnerability directly to a Device (host-level finding).

    Use this for vulnerabilities that affect the device itself rather than a
    specific service — for example, weak SSH host keys, missing patches, or
    exposed debug interfaces.

    You MUST provide a valid ``device_id`` obtained from add_device().

    Args:
        device_id: Registry ID of the target Device.
        title: Short vulnerability title.
        description: Detailed finding description.
        threat: Threat level label (e.g. ``"critical"``, ``"high"``).
        cvss: CVSS score (integer 0-10).
        risk_json: JSON object with ``likelihood``, ``impact``, ``severity``.
        verified: Whether the vulnerability has been confirmed.

    Returns:
        Confirmation with the vulnerability ID.
    """
    from wintermute.core import Device

    dev: Device = _require(device_id, Device, "Device")
    return _add_vuln_to(dev, title, description, threat, cvss, risk_json, verified)


@mcp.tool()
async def addVulnerability_Service(
    service_id: str,
    title: str,
    description: str | None = None,
    threat: str | None = None,
    cvss: int | None = None,
    risk_json: str | None = None,
    verified: bool | None = None,
) -> str:
    """Add a vulnerability to a network Service.

    Use this for service-level findings like SQL injection, XSS, missing HSTS,
    or TLS misconfigurations.

    You MUST provide a valid ``service_id`` obtained from add_service_to_device().

    Args:
        service_id: Registry ID of the target Service.
        title: Short vulnerability title.
        description: Detailed finding description.
        threat: Threat level label.
        cvss: CVSS score (integer 0-10).
        risk_json: JSON object with ``likelihood``, ``impact``, ``severity``.
        verified: Whether the vulnerability has been confirmed.

    Returns:
        Confirmation with the vulnerability ID.
    """
    from wintermute.core import Service

    svc: Service = _require(service_id, Service, "Service")
    return _add_vuln_to(svc, title, description, threat, cvss, risk_json, verified)


@mcp.tool()
async def addVulnerability_AWSAccount(
    aws_account_id: str,
    title: str,
    description: str | None = None,
    threat: str | None = None,
    cvss: int | None = None,
    risk_json: str | None = None,
    verified: bool | None = None,
) -> str:
    """Add a vulnerability to an AWS Account.

    Use this for cloud-level findings like overly permissive IAM policies,
    public S3 buckets, or missing CloudTrail logging.

    You MUST provide a valid ``aws_account_id`` obtained from add_aws_account().

    Args:
        aws_account_id: Registry ID of the target AWSAccount.
        title: Short vulnerability title.
        description: Detailed finding description.
        threat: Threat level label.
        cvss: CVSS score (integer 0-10).
        risk_json: JSON object with ``likelihood``, ``impact``, ``severity``.
        verified: Whether the vulnerability has been confirmed.

    Returns:
        Confirmation with the vulnerability ID.
    """
    acc: AWSAccount = _require(aws_account_id, AWSAccount, "AWSAccount")
    return _add_vuln_to(acc, title, description, threat, cvss, risk_json, verified)


@mcp.tool()
async def addVulnerability_User(
    user_id: str,
    title: str,
    description: str | None = None,
    threat: str | None = None,
    cvss: int | None = None,
    risk_json: str | None = None,
    verified: bool | None = None,
) -> str:
    """Add a vulnerability to a User account.

    Use this for user-level findings like weak passwords, credential reuse,
    excessive permissions, or successful phishing.

    You MUST provide a valid ``user_id`` obtained from add_user().

    Args:
        user_id: Registry ID of the target User.
        title: Short vulnerability title.
        description: Detailed finding description.
        threat: Threat level label.
        cvss: CVSS score (integer 0-10).
        risk_json: JSON object with ``likelihood``, ``impact``, ``severity``.
        verified: Whether the vulnerability has been confirmed.

    Returns:
        Confirmation with the vulnerability ID.
    """
    from wintermute.core import User

    user: User = _require(user_id, User, "User")
    return _add_vuln_to(user, title, description, threat, cvss, risk_json, verified)


@mcp.tool()
async def addVulnerability_Peripheral(
    peripheral_id: str,
    title: str,
    description: str | None = None,
    threat: str | None = None,
    cvss: int | None = None,
    risk_json: str | None = None,
    verified: bool | None = None,
) -> str:
    """Add a vulnerability to a hardware Peripheral (UART, JTAG, etc.).

    Use this for hardware-level findings like unauthenticated UART root shell,
    exposed JTAG debug port, or SWD readout not disabled.

    You MUST provide a valid ``peripheral_id`` obtained from
    add_peripheral_to_device().

    Args:
        peripheral_id: Registry ID of the target Peripheral.
        title: Short vulnerability title.
        description: Detailed finding description.
        threat: Threat level label.
        cvss: CVSS score (integer 0-10).
        risk_json: JSON object with ``likelihood``, ``impact``, ``severity``.
        verified: Whether the vulnerability has been confirmed.

    Returns:
        Confirmation with the vulnerability ID.
    """
    from wintermute.basemodels import Peripheral

    periph: Peripheral = _require(peripheral_id, Peripheral, "Peripheral")
    return _add_vuln_to(periph, title, description, threat, cvss, risk_json, verified)


@mcp.tool()
async def remove_vulnerability_from_target(
    target_id: str,
    vuln_title: str | None = None,
    vuln_id: str | None = None,
) -> str:
    """Remove a vulnerability from any registered target object.

    Provide either ``vuln_title`` or ``vuln_id`` to identify the vulnerability.

    Args:
        target_id: Registry ID of the object holding the vulnerability.
        vuln_title: Title of the vulnerability to remove (optional).
        vuln_id: UUID of the vulnerability to remove (optional).

    Returns:
        Confirmation or error message.
    """
    obj = registry.get(target_id)
    if obj is None:
        return f"ID '{target_id}' not found."
    kwargs: dict[str, str] = {}
    if vuln_id:
        kwargs["uid"] = vuln_id
    elif vuln_title:
        kwargs["title"] = vuln_title
    else:
        return "Provide at least 'vuln_title' or 'vuln_id'."
    result = remove_vulnerability(obj, **kwargs)
    return f"Vulnerability removed: {result}"


# ═══════════════════════════════════════════════════════════════════════════
#  I.  CONTEXT RETRIEVAL — The Agent's "Eyes"
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def get_device_info(device_id: str) -> str:
    """Return all known properties of a Device including services and peripherals.

    Use this to see open ports, JTAG/UART configurations, processor details,
    and attached vulnerabilities before deciding what to exploit or test.

    Args:
        device_id: Registry ID of the target Device.

    Returns:
        Full JSON representation of the Device.
    """
    from wintermute.core import Device

    dev: Device = _require(device_id, Device, "Device")
    return _ser(dev)


@mcp.tool()
async def get_cloud_account_info(cloud_account_id: str) -> str:
    """Return all known properties of a Cloud/AWS Account.

    Includes IAM users, IAM roles, services, tags, and attached
    vulnerabilities.  Use this to map the attack surface of a cloud account.

    Args:
        cloud_account_id: Registry ID of the target Cloud/AWS Account.

    Returns:
        Full JSON representation of the account.
    """
    acc = registry.get(cloud_account_id)
    if acc is None:
        return f"ID '{cloud_account_id}' not found."
    return _ser(acc)


@mcp.tool()
async def list_target_vulnerabilities(target_id: str) -> str:
    """List all vulnerabilities currently registered on a specific target.

    The ``target_id`` can be any object that holds vulnerabilities: Device,
    Service, AWSAccount, User, or Peripheral.  Use this to know what has
    already been found before running additional tests.

    Args:
        target_id: Registry ID of the target object.

    Returns:
        JSON array of vulnerability summaries (title, cvss, vuln_id, threat).
    """
    obj = registry.get(target_id)
    if obj is None:
        return f"ID '{target_id}' not found."
    vulns: list[Vulnerability] = getattr(obj, "vulnerabilities", [])
    summaries = [
        {
            "vuln_id": v.vuln_id,
            "title": v.title,
            "cvss": v.cvss,
            "threat": v.threat,
            "verified": v.verified,
        }
        for v in vulns
    ]
    if not summaries:
        return f"No vulnerabilities on {target_id}."
    return json.dumps(summaries, indent=2)


@mcp.tool()
async def get_user_info(user_id: str) -> str:
    """Return all known properties of a User including teams and permissions.

    Args:
        user_id: Registry ID of the target User.

    Returns:
        Full JSON representation of the User.
    """
    from wintermute.core import User

    user: User = _require(user_id, User, "User")
    return _ser(user)


@mcp.tool()
async def get_test_plan_info(test_plan_id: str) -> str:
    """Return the full content of a test plan including all test cases.

    Args:
        test_plan_id: Registry ID of the target TestPlan.

    Returns:
        Full JSON representation of the TestPlan.
    """
    tp: TestPlan = _require(test_plan_id, TestPlan, "TestPlan")
    return _ser(tp)


@mcp.tool()
async def get_test_run_info(test_run_id: str) -> str:
    """Return the current state of a test case run.

    Includes status, timestamps, bound targets, findings, and notes.

    Args:
        test_run_id: Registry ID of the TestCaseRun.

    Returns:
        Full JSON representation of the TestCaseRun.
    """
    run: TestCaseRun = _require(test_run_id, TestCaseRun, "TestCaseRun")
    return _ser(run)


# ═══════════════════════════════════════════════════════════════════════════
#  J.  CARTRIDGES
# ═══════════════════════════════════════════════════════════════════════════

_loaded_cartridges: dict[str, Any] = {}


@mcp.tool()
async def list_cartridges() -> str:
    """List all available Wintermute cartridge plugins.

    Cartridges are located in ``wintermute/cartridges/``.  Each cartridge
    provides specialized hardware or offensive testing capabilities.

    Returns:
        JSON object with available and currently loaded cartridge names.
    """
    import pkgutil

    import wintermute.cartridges as pkg

    available: list[str] = []
    for _importer, modname, _ispkg in pkgutil.iter_modules(pkg.__path__):
        if not modname.startswith("_"):
            available.append(modname)
    return json.dumps(
        {"available": available, "loaded": list(_loaded_cartridges.keys())},
        indent=2,
    )


@mcp.tool()
async def load_cartridge(cartridge_name: str) -> str:
    """Load a cartridge plugin by name.

    The cartridge module is imported and its main class (if any) is
    instantiated.  Use list_cartridges() first to see available names.

    Args:
        cartridge_name: Module name (e.g. ``"tpm20"``).

    Returns:
        Confirmation with the cartridge's available methods/classes.
    """
    if cartridge_name in _loaded_cartridges:
        return f"Cartridge '{cartridge_name}' is already loaded."
    try:
        mod = importlib.import_module(f"wintermute.cartridges.{cartridge_name}")
        _loaded_cartridges[cartridge_name] = mod
        members = [n for n in dir(mod) if not n.startswith("_")]
        return f"Loaded '{cartridge_name}'. Exports: {members}"
    except Exception as e:
        return f"Failed to load cartridge '{cartridge_name}': {e}"


@mcp.tool()
async def unload_cartridge(cartridge_name: str) -> str:
    """Unload a previously loaded cartridge.

    Args:
        cartridge_name: Module name to unload.

    Returns:
        Confirmation or error.
    """
    if cartridge_name in _loaded_cartridges:
        del _loaded_cartridges[cartridge_name]
        fqn = f"wintermute.cartridges.{cartridge_name}"
        sys.modules.pop(fqn, None)
        return f"Unloaded '{cartridge_name}'."
    return f"Cartridge '{cartridge_name}' is not loaded."


@mcp.tool()
async def execute_tpm20_get_random(
    device_path: str | None = None,
    num_bytes: int | None = None,
) -> str:
    """Execute the TPM 2.0 GetRandom command via the tpm20 cartridge.

    Requires the ``tpm20`` cartridge to be loaded and a TPM device accessible
    at ``device_path``.

    Args:
        device_path: Path to the TPM device (default ``"/dev/tpm0"``).
        num_bytes: Number of random bytes to request (1-64).

    Returns:
        Hex-encoded random bytes or error.
    """
    if "tpm20" not in _loaded_cartridges:
        return "Cartridge 'tpm20' not loaded. Call load_cartridge('tpm20') first."
    mod = _loaded_cartridges["tpm20"]
    try:
        transport = mod.TPMTransport(device_path=device_path or "/dev/tpm0")
        tpm = mod.tpm20(transport=transport)
        data: bytes = tpm.get_random(num_bytes if num_bytes is not None else 16)
        return f"Random bytes ({len(data)}): {data.hex()}"
    except Exception as e:
        return f"TPM GetRandom failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════
#  K.  AI & UTILITIES
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def ai_chat(prompt: str, task_tag: str | None = None) -> str:
    """Send a one-shot prompt to the configured LLM and return the response.

    You MUST call configure_ai_router() before using this tool.

    Args:
        prompt: The question or instruction for the LLM.
        task_tag: Routing hint.  Use ``"cheap"`` to route to Groq for fast
                  inexpensive queries.

    Returns:
        The LLM's text response.
    """
    router = _router()
    if router is None:
        return "AI router not initialized. Call configure_ai_router() first."
    try:
        return simple_chat(router, prompt, task_tag or "generic")
    except Exception as e:
        return f"AI chat failed: {e}"


@mcp.tool()
async def enrich_processor_via_ai(
    processor_name: str,
    manufacturer: str | None = None,
) -> str:
    """Use AI to enrich a processor with architecture and capability details.

    Creates a minimal Processor object and queries the LLM to fill in ISA,
    core count, security features, pinout, and known vulnerabilities.

    You MUST call configure_ai_router() first.

    Args:
        processor_name: Processor name/model (e.g. ``"STM32F407"``).
        manufacturer: Manufacturer name (e.g. ``"STMicroelectronics"``).

    Returns:
        JSON representation of the enriched Processor.
    """
    from wintermute.ai.utils.hardware import enrich_processor

    proc = Processor(processor=processor_name, manufacturer=manufacturer or None)
    try:
        enriched = enrich_processor(proc, router=_router())
        pid = registry.store(enriched, "processor", processor_name, prefix="proc")
        result = enriched.to_dict()
        result["_registry_id"] = pid
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return f"Enrichment failed: {e}"


@mcp.tool()
async def set_device_processor(
    device_id: str,
    processor_name: str,
    manufacturer: str | None = None,
    instruction_set: str | None = None,
    core: str | None = None,
    cpu_cores: int | None = None,
    endianness: str | None = None,
) -> str:
    """Assign a Processor and Architecture to a Device.

    Use this after identifying the target's CPU (e.g. from board markings,
    firmware headers, or JTAG IDCODE).

    Args:
        device_id: Registry ID of the target Device.
        processor_name: Processor name/model (e.g. ``"Cortex-A7"``).
        manufacturer: Manufacturer (e.g. ``"ARM"``).
        instruction_set: ISA (e.g. ``"ARMv7-A"``).
        core: Core type (e.g. ``"Cortex-A7"``).
        cpu_cores: Number of CPU cores.
        endianness: ``"little"`` or ``"big"``.

    Returns:
        Confirmation message.
    """
    from wintermute.core import Device

    dev: Device = _require(device_id, Device, "Device")
    arch_kwargs: dict[str, Any] = {}
    if core:
        arch_kwargs["core"] = core
    if instruction_set:
        arch_kwargs["instruction_set"] = instruction_set
    if cpu_cores:
        arch_kwargs["cpu_cores"] = cpu_cores
    arch = Architecture(**arch_kwargs) if arch_kwargs else None
    proc = Processor(
        processor=processor_name,
        manufacturer=manufacturer or None,
        architecture=arch or {},
        endianness=endianness or None,
    )
    dev.processor = proc
    if arch:
        dev.architecture = arch
    return f"Processor '{processor_name}' assigned to {device_id}."


@mcp.tool()
async def analyze_test_coverage(operation_id: str) -> str:
    """Analyze test coverage across all assets in an Operation.

    Categorizes test runs by asset type (EC2, S3, IAM, Device, etc.) and
    returns a coverage breakdown.

    Args:
        operation_id: Registry ID of the parent Operation.

    Returns:
        JSON object mapping asset categories to test run counts.
    """
    from wintermute.utils.coverage import analyze_coverage

    op: Operation = _require(operation_id, Operation, "Operation")
    result = analyze_coverage(op)
    return json.dumps(result, indent=2)


@mcp.tool()
async def register_python_tools(function_names_json: str) -> str:
    """Register Python functions as AI-callable tools in the global registry.

    Each function must be importable and have full type annotations.

    Args:
        function_names_json: JSON array of fully-qualified function names
                             (e.g. ``'["mymodule.my_func"]'``).

    Returns:
        List of registered tool names, or errors.
    """
    from wintermute.ai.utils.tool_factory import register_tools

    try:
        names: list[str] = json.loads(function_names_json)
    except json.JSONDecodeError:
        return "Invalid JSON array."
    functions: list[Any] = []
    for name in names:
        parts = name.rsplit(".", 1)
        if len(parts) != 2:
            return f"Invalid function path: '{name}'. Use 'module.function' format."
        mod = importlib.import_module(parts[0])
        functions.append(getattr(mod, parts[1]))
    tools_created = register_tools(functions)
    for t in tools_created:
        global_tool_registry.register(t)
    return f"Registered {len(tools_created)} tools: {[t.name for t in tools_created]}"


@mcp.tool()
async def list_registered_ai_tools() -> str:
    """List all tools currently registered in the Wintermute AI tool registry.

    These are the tools available for LLM function-calling via
    tool_calling_chat().

    Returns:
        JSON array of tool definitions (name, description, parameters).
    """
    defs = global_tool_registry.get_definitions()
    return json.dumps(defs, indent=2)


@mcp.tool()
async def generate_strategy_report(operation_id: str) -> str:
    """Use AI to generate an execution strategy report for an Operation.

    Analyzes all test runs, findings, and targets in the Operation and
    produces a markdown-formatted strategy document.

    You MUST call configure_ai_router() first.

    Args:
        operation_id: Registry ID of the parent Operation.

    Returns:
        Markdown-formatted strategy report text.
    """
    from wintermute.ai.reporting import generate_execution_strategy_report

    router = _router()
    if router is None:
        return "AI router not initialized. Call configure_ai_router() first."
    op: Operation = _require(operation_id, Operation, "Operation")
    try:
        return generate_execution_strategy_report(router, op)
    except Exception as e:
        return f"Strategy report failed: {e}"


# ═══════════════════════════════════════════════════════════════════════════
#  L.  ACTIVE EXECUTION & INGESTION — The Agent's "Hands"
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def ingest_burp_scan(
    operation_id: str,
    burp_xml_path: str,
) -> str:
    """Parse a Burp Suite XML export and add discovered hosts to an Operation.

    The parser extracts Devices, Services, and Vulnerabilities from the Burp
    XML format and registers them in both the Operation and the session
    registry.

    Args:
        operation_id: Registry ID of the target Operation.
        burp_xml_path: Filesystem path to the Burp XML file.

    Returns:
        Summary of ingested devices, services, and vulnerabilities.
    """
    from wintermute.utils.parsers import BurpParser

    op: Operation = _require(operation_id, Operation, "Operation")
    parser = BurpParser()
    try:
        devices = parser.parse(file=burp_xml_path)
    except Exception as e:
        return f"Burp parse failed: {e}"

    dev_ids: list[str] = []
    total_svcs = 0
    total_vulns = 0
    for dev in devices:
        # Merge into operation — addDevice handles merge-on-hostname
        op.addDevice(
            dev.hostname, str(dev.ipaddr), dev.macaddr, dev.operatingsystem, dev.fqdn
        )
        existing = op.getDeviceByHostname(dev.hostname)
        if existing is None:
            continue
        # Merge services
        for svc in dev.services:
            existing.addService(
                protocol=svc.protocol,
                app=svc.app,
                portNumber=svc.portNumber,
                banner=svc.banner,
                transport_layer=svc.transport_layer,
            )
            total_svcs += 1
            for v in svc.vulnerabilities:
                existing.services[-1].addVulnerability(
                    title=v.title,
                    description=v.description,
                    threat=v.threat,
                    cvss=v.cvss,
                )
                total_vulns += 1
        did = registry.store(existing, "device", dev.hostname, prefix="dev")
        dev_ids.append(did)

    return json.dumps(
        {
            "devices_ingested": len(dev_ids),
            "services_ingested": total_svcs,
            "vulnerabilities_ingested": total_vulns,
            "device_ids": dev_ids,
        },
        indent=2,
    )


@mcp.tool()
async def attach_evidence(
    target_id: str,
    vuln_title: str,
    artifact_data: str,
    artifact_title: str | None = None,
    tool: str | None = None,
    action: str | None = None,
) -> str:
    """Attach evidence (crash dump, token, PoC output) to a vulnerability.

    This creates a ReproductionStep on the specified vulnerability with the
    artifact data stored in the ``vulnOutput`` field.  Use this to log proof
    of exploitation or raw tool output.

    Args:
        target_id: Registry ID of the object holding the vulnerability.
        vuln_title: Title of the vulnerability to attach evidence to.
        artifact_data: The raw evidence content (text, base64, hex dump, etc.).
        artifact_title: Short label for this evidence item.
        tool: Tool that produced this evidence (e.g. ``"gdb"``, ``"nmap"``).
        action: Action performed (e.g. ``"exploit"``, ``"dump"``).

    Returns:
        Confirmation or error message.
    """
    obj = registry.get(target_id)
    if obj is None:
        return f"ID '{target_id}' not found."
    step = ReproductionStep(
        title=artifact_title or "evidence",
        description="Evidence attached by agent",
        tool=tool or None,
        action=action or None,
        confidence=100,
        vulnOutput=artifact_data,
    )
    result = add_reproduction_step(obj, title=vuln_title, step=step)
    if result:
        return f"Evidence '{artifact_title}' attached to vulnerability '{vuln_title}'."
    vuln = get_vulnerability(obj, title=vuln_title)
    if vuln is None:
        return f"Vulnerability '{vuln_title}' not found on {target_id}."
    vuln.reproduction_steps.append(step)
    return f"Evidence '{artifact_title}' attached to vulnerability '{vuln_title}'."


@mcp.tool()
async def execute_depthcharge_catalog(
    peripheral_id: str,
    add_vulns: bool | None = None,
) -> str:
    """Run Depthcharge command cataloging against a UART peripheral.

    Connects to the U-Boot console via the peripheral's device_path, enumerates
    all available commands, scores them for danger, and optionally adds
    vulnerabilities for dangerous commands.

    REQUIRES: Physical access to the target device's UART console running
    U-Boot, and the ``depthcharge`` Python package.

    Args:
        peripheral_id: Registry ID of the target UART Peripheral.
        add_vulns: If True, automatically create vulnerabilities for dangerous
                   commands found.

    Returns:
        JSON summary of discovered commands and danger analysis.
    """
    from wintermute.backends.depthcharge import DepthchargePeripheralAgent
    from wintermute.basemodels import Peripheral

    periph: Peripheral = _require(peripheral_id, Peripheral, "Peripheral")
    try:
        agent = DepthchargePeripheralAgent(peripheral=periph)  # type: ignore[arg-type]
        result = agent.catalog_commands_and_flag(
            addVulns=add_vulns if add_vulns is not None else True
        )
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return f"Depthcharge catalog failed: {e}"


@mcp.tool()
async def execute_depthcharge_memory_dump(
    peripheral_id: str,
    address: str,
    length: int,
    filename: str | None = None,
) -> str:
    """Dump memory from a U-Boot target via Depthcharge.

    Connects to the U-Boot console and reads raw memory.  The dump is saved
    to disk and a vulnerability is automatically created if successful.

    REQUIRES: Physical access to the target device's UART console running
    U-Boot.

    Args:
        peripheral_id: Registry ID of the target UART Peripheral.
        address: Start address as a hex string (e.g. ``"0x80000000"``).
        length: Number of bytes to dump.
        filename: Output filename (auto-generated if empty).

    Returns:
        JSON summary with file path and SHA256 hash.
    """
    from wintermute.backends.depthcharge import DepthchargePeripheralAgent
    from wintermute.basemodels import Peripheral

    periph: Peripheral = _require(peripheral_id, Peripheral, "Peripheral")
    try:
        agent = DepthchargePeripheralAgent(peripheral=periph)  # type: ignore[arg-type]
        addr_int = int(address, 16) if address.startswith("0x") else int(address)
        result = agent.dump_memory_and_attach_vuln(
            address=addr_int,
            length=length,
            filename=filename or None,
        )
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return f"Memory dump failed: {e}"


@mcp.tool()
async def run_ssh_command(
    target_alias: str,
    command: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> str:
    """Execute a command on a remote host via SSH.

    Uses asyncssh and the host machine's ``~/.ssh/config`` for proxy jumping,
    key management, and host aliases.

    Args:
        target_alias: SSH host alias from ~/.ssh/config, or hostname/IP.
        command: Shell command to execute on the remote host.
        username: SSH username (optional — inferred from ssh config).
        password: SSH password (optional — falls back to key-based auth).
        port: SSH port (optional — defaults to ssh config or 22).

    Returns:
        JSON with ``stdout``, ``stderr``, and ``exit_code``.
    """
    from wintermute.ai.utils.ssh_exec import run_command_async

    result = await run_command_async(
        target_alias=target_alias,
        command=command,
        username=username,
        password=password,
        port=port,
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def upload_file_ssh(
    target_alias: str,
    local_path: str,
    remote_path: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> str:
    """Upload a file to a remote host via SFTP/SSH.

    Uses asyncssh and the host machine's ``~/.ssh/config`` for proxy jumping,
    key management, and host aliases.

    Args:
        target_alias: SSH host alias from ~/.ssh/config, or hostname/IP.
        local_path: Local file path to upload.
        remote_path: Destination path on the remote host.
        username: SSH username (optional — inferred from ssh config).
        password: SSH password (optional — falls back to key-based auth).
        port: SSH port (optional — defaults to ssh config or 22).

    Returns:
        Confirmation or error message.
    """
    from wintermute.ai.utils.ssh_exec import upload_file_async

    result = await upload_file_async(
        target_alias=target_alias,
        local_path=local_path,
        remote_path=remote_path,
        username=username,
        password=password,
        port=port,
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def download_file_ssh(
    target_alias: str,
    remote_path: str,
    local_path: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> str:
    """Download a file from a remote host via SFTP/SSH.

    Uses asyncssh and the host machine's ``~/.ssh/config`` for proxy jumping,
    key management, and host aliases.

    Args:
        target_alias: SSH host alias from ~/.ssh/config, or hostname/IP.
        remote_path: File path on the remote host to download.
        local_path: Local destination path for the downloaded file.
        username: SSH username (optional — inferred from ssh config).
        password: SSH password (optional — falls back to key-based auth).
        port: SSH port (optional — defaults to ssh config or 22).

    Returns:
        Confirmation or error message.
    """
    from wintermute.ai.utils.ssh_exec import download_file_async

    result = await download_file_async(
        target_alias=target_alias,
        remote_path=remote_path,
        local_path=local_path,
        username=username,
        password=password,
        port=port,
    )
    return json.dumps(result, indent=2, default=str)


# --- Persistent SSH Sessions ---


@mcp.tool()
async def open_ssh_session(
    target_alias: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> str:
    """Open a persistent SSH session for multi-command workflows.

    Use this instead of ``run_ssh_command`` when you need to run many commands
    on the same target, launch background fuzzers or long-running tools, or
    preserve shell state across calls.  The session stays open until you
    explicitly call ``close_ssh_session``.

    Args:
        target_alias: SSH host alias from ~/.ssh/config, or hostname/IP.
        username: SSH username (optional — inferred from ssh config).
        password: SSH password (optional — falls back to key-based auth).
        port: SSH port (optional — defaults to ssh config or 22).

    Returns:
        A session_id string for use with the other ``*_ssh_session*`` tools.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session = SSHSession(
            target_alias=target_alias,
            username=username,
            password=password,
            port=port,
        )
        await session.connect()
        session_id = registry.store(session, "ssh_session", target_alias, prefix="ssh")
        return json.dumps({"session_id": session_id}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to open SSH session: {e}"}, indent=2)


@mcp.tool()
async def run_ssh_session_command(session_id: str, command: str) -> str:
    """Execute a command on a persistent SSH session.

    Args:
        session_id: ID returned by ``open_ssh_session``.
        command: Shell command to execute.

    Returns:
        JSON with ``exit_code``, ``stdout``, and ``stderr``.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session: SSHSession = _require(session_id, SSHSession, "SSHSession")
        result = await session.run(command)
        return json.dumps(result, indent=2, default=str)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def run_ssh_session_background(session_id: str, command: str) -> str:
    """Launch a background command on a persistent SSH session.

    Use this for fuzzers, long scanners, or any tool that may run for minutes
    or hours.  Poll with ``poll_ssh_background_job`` to check completion.

    Args:
        session_id: ID returned by ``open_ssh_session``.
        command: Shell command to launch in the background via nohup.

    Returns:
        JSON with the ``job_id`` to use when polling.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session: SSHSession = _require(session_id, SSHSession, "SSHSession")
        job_id = await session.run_background(command)
        return json.dumps({"job_id": job_id}, indent=2)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def poll_ssh_background_job(session_id: str, job_id: str) -> str:
    """Poll the status of a background job on a persistent SSH session.

    Do NOT block in a loop — call this tool, read the status, and if still
    ``"running"`` wait before calling again.  This is the correct pattern for
    long-running tools.

    Args:
        session_id: ID returned by ``open_ssh_session``.
        job_id: ID returned by ``run_ssh_session_background``.

    Returns:
        JSON with ``status`` (``"running"``, ``"done"``, or ``"error"``),
        and ``exit_code``, ``stdout``, ``stderr`` when finished.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session: SSHSession = _require(session_id, SSHSession, "SSHSession")
        result = await session.poll_job(job_id)
        return json.dumps(result, indent=2, default=str)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def close_ssh_session(session_id: str) -> str:
    """Close a persistent SSH session and release its resources.

    Args:
        session_id: ID returned by ``open_ssh_session``.

    Returns:
        Confirmation message.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session: SSHSession = _require(session_id, SSHSession, "SSHSession")
        await session.close()
        registry.delete(session_id)
        return json.dumps({"result": f"Session {session_id} closed."}, indent=2)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def upload_file_ssh_session(
    session_id: str, local_path: str, remote_path: str
) -> str:
    """Upload a file via SFTP on a persistent SSH session.

    Args:
        session_id: ID returned by ``open_ssh_session``.
        local_path: Local file path to upload.
        remote_path: Destination path on the remote host.

    Returns:
        Confirmation or error message.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session: SSHSession = _require(session_id, SSHSession, "SSHSession")
        result = await session.upload(local_path, remote_path)
        return json.dumps(result, indent=2, default=str)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def download_file_ssh_session(
    session_id: str, remote_path: str, local_path: str
) -> str:
    """Download a file via SFTP on a persistent SSH session.

    Args:
        session_id: ID returned by ``open_ssh_session``.
        remote_path: File path on the remote host to download.
        local_path: Local destination path for the downloaded file.

    Returns:
        Confirmation or error message.
    """
    from wintermute.ai.utils.ssh_exec import SSHSession

    try:
        session: SSHSession = _require(session_id, SSHSession, "SSHSession")
        result = await session.download(remote_path, local_path)
        return json.dumps(result, indent=2, default=str)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)}, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    """CLI entry point for the Wintermute MCP Server."""
    parser = argparse.ArgumentParser(
        description="Wintermute MCP Server — Hardware Security AI Agent Interface",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=31337,
        help="Bind port (default: 31337)",
    )
    parser.add_argument(
        "--transport",
        choices=["sse", "stdio"],
        default="sse",
        help="MCP transport (default: sse)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.transport == "sse":
        # Configure FastMCP settings for SSE transport
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        log.info("Starting WintermuteMCP on %s:%d (SSE)", args.host, args.port)
        mcp.run(transport="sse")
    else:
        log.info("Starting WintermuteMCP on stdio")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
