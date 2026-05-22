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

import asyncio
import asyncio.subprocess
import concurrent.futures
import json
import logging
import os
import threading
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage
from pydantic import BaseModel, Field

# Wintermute imports
from wintermute.ai.json_types import JSONObject
from wintermute.ai.tools_runtime import Tool
from wintermute.ai.tools_runtime import tools as global_registry
from wintermute.ai.types import ToolSpec

log = logging.getLogger(__name__)


class MCPRuntime:
    """
    Manages the lifecycle of an MCP connection and registers its tools
    into the Wintermute ToolRegistry.

    The connection is described by a config dictionary. Two transport types
    are supported:

    * ``{"type": "stdio", "command": "...", "args": [...], "env": {...}}``
      spawns a local subprocess and speaks JSON-RPC over its stdio.
    * ``{"type": "sse", "url": "http://host:port/sse", "headers": {...}}``
      connects to a remote MCP server over HTTP Server-Sent Events. Used
      for remote hardware nodes that expose their tools over the network.

    For backward compatibility, the legacy stdio-only ``command``/``args``/
    ``env`` keyword form is still accepted and internally rewritten into a
    stdio config.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        if config is None:
            if command is None:
                raise ValueError(
                    "MCPRuntime requires either a 'config' dict or a legacy "
                    "'command' argument for stdio mode"
                )
            config = {
                "type": "stdio",
                "command": command,
                "args": list(args) if args is not None else [],
                "env": env,
            }

        transport = config.get("type", "stdio")
        if transport not in ("stdio", "sse"):
            raise ValueError(
                f"Unsupported MCP transport {transport!r}; expected 'stdio' or 'sse'"
            )
        if transport == "stdio" and "command" not in config:
            raise ValueError("stdio MCP config requires a 'command' field")
        if transport == "sse" and "url" not in config:
            raise ValueError("sse MCP config requires a 'url' field")

        self.config: Dict[str, Any] = config
        self.transport: str = transport
        self.session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None

    async def initialize(self) -> None:
        """Connects to MCP and registers tools into Wintermute's global registry."""
        self._exit_stack = AsyncExitStack()

        # 1. Connect via the configured transport.
        # We explicitly assert to satisfy mypy that _exit_stack is initialized
        assert self._exit_stack is not None

        if self.transport == "stdio":
            server_params = StdioServerParameters(
                command=self.config["command"],
                args=list(self.config.get("args", []) or []),
                env=self.config.get("env"),
            )
            read, write = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )
        else:  # sse
            streams = await self._exit_stack.enter_async_context(
                sse_client(
                    url=self.config["url"],
                    headers=self.config.get("headers"),
                )
            )
            # sse_client yields (read_stream, write_stream); accept extras defensively.
            read, write = streams[0], streams[1]

        self.session = await self._exit_stack.enter_async_context(
            ClientSession(read, write)
        )
        await self.session.initialize()

        # 2. List Tools from MCP
        mcp_tools = await self.session.list_tools()

        # 3. Register as Wintermute Tools
        for mt in mcp_tools.tools:
            # We create a closure to bind the tool name for the handler
            def make_handler(tool_name: str) -> Any:
                def handler(args: JSONObject) -> JSONObject:
                    # Wintermute expects a synchronous return (JSONObject), but MCP is async.
                    # We return the Coroutine object and rely on run_surgeon.py to await it.
                    # We use cast() to silence mypy complaining about returning a Coroutine.
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()

                    # Convert Mapping to Dict for MCP
                    mcp_args = cast(Dict[str, Any], args)

                    if loop.is_running():
                        return cast(
                            JSONObject, self._execute_mcp_tool(tool_name, mcp_args)
                        )
                    else:
                        return loop.run_until_complete(
                            self._execute_mcp_tool(tool_name, mcp_args)
                        )

                return handler

            # Create Wintermute Tool
            wm_tool = Tool(
                name=mt.name,
                input_schema=mt.inputSchema,
                output_schema={},
                handler=make_handler(mt.name),
            )

            # Register in wintermute/ai/tools_runtime.py
            global_registry.register(wm_tool)
            # print(f"[*] Registered MCP Tool: {mt.name}")

    async def _execute_mcp_tool(
        self, name: str, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Actual execution logic."""
        if not self.session:
            raise RuntimeError("MCP Session is not initialized")

        result = await self.session.call_tool(name, args)

        # Flatten content blocks to a single string for the LLM
        output_text = []
        if result.content:
            for c in result.content:
                if c.type == "text":
                    # Accessing .text is safe here because we checked type == 'text'
                    output_text.append(c.text)
                elif c.type == "image":
                    output_text.append("[Image Data]")
                elif (
                    c.type == "resource"
                ):  # <--- FIXED: Changed from "embedded_resource" to "resource"
                    output_text.append("[Embedded Resource]")
                # We can ignore 'audio' or 'resource_link' for text-based LLM output for now

        return {"output": "\n".join(output_text)}

    async def shutdown(self) -> None:
        if self._exit_stack:
            await self._exit_stack.aclose()


# ---------------------------------------------------------------------------
# MCPClientManager — config-backed lifecycle for outbound MCP stdio clients
# ---------------------------------------------------------------------------


_DEFAULT_CONFIG_PATH = Path.home() / ".wintermute" / "mcp_servers.json"

# Init/handshake timeout for a single MCP stdio server. 10s is long enough for
# Ghidra-style heavy startups and short enough that a wedged subprocess does
# not strand the daemon thread for the rest of the session.
_INIT_TIMEOUT_SECONDS: float = 10.0

# Bounded timeout for the synchronous stop_server -> background-loop hop. The
# UI thread MUST cap this so a stuck subprocess can't pin the prompt.
_STOP_TIMEOUT_SECONDS: float = 5.0


class MCPServerDefinition(BaseModel):
    """Persisted definition of an external MCP server.

    Stored in ``~/.wintermute/mcp_servers.json`` as a JSON array. Each entry
    captures the spawn recipe for a stdio MCP server the operator wants the
    console to connect to (Ghidra, Binary Ninja, custom helpers, etc.).
    """

    name: str
    command: str
    args: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Manual stdio plumbing — gives us the real asyncio subprocess handle so the
# stop path can SIGTERM/SIGKILL it directly. The MCP SDK's own ``stdio_client``
# hides the process inside an anyio task group; that is fine for happy paths
# but leaves zombie processes when the server hangs at init or refuses to
# acknowledge close. By spawning ourselves we keep the kill switch.
# ---------------------------------------------------------------------------


async def _stdout_to_session_stream(
    process: asyncio.subprocess.Process,
    sender: anyio.streams.memory.MemoryObjectSendStream[Any],
) -> None:
    """Read newline-delimited JSON-RPC frames from ``process.stdout`` and push
    them into ``sender`` as :class:`SessionMessage` instances.

    Malformed lines are forwarded as exceptions so the ``ClientSession`` can
    surface them to the caller rather than silently dropping data.
    """
    assert process.stdout is not None
    buffer = b""
    try:
        while True:
            chunk = await process.stdout.read(4096)
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                raw_line, buffer = buffer.split(b"\n", 1)
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    message = JSONRPCMessage.model_validate_json(line)
                    session_message = SessionMessage(message=message)
                except Exception as exc:
                    try:
                        await sender.send(exc)
                    except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                        return
                    continue
                try:
                    await sender.send(session_message)
                except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                    return
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("MCP stdout pump crashed")
    finally:
        try:
            await sender.aclose()
        except Exception:
            pass


async def _session_stream_to_stdin(
    process: asyncio.subprocess.Process,
    receiver: anyio.streams.memory.MemoryObjectReceiveStream[Any],
) -> None:
    """Pump :class:`SessionMessage` instances from ``receiver`` into the
    subprocess's stdin as newline-delimited JSON-RPC frames."""
    assert process.stdin is not None
    try:
        async with receiver:
            async for session_message in receiver:
                payload = session_message.message.model_dump_json(
                    by_alias=True, exclude_none=True
                )
                line = (payload + "\n").encode("utf-8")
                process.stdin.write(line)
                try:
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    return
    except (anyio.BrokenResourceError, anyio.ClosedResourceError):
        return
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("MCP stdin pump crashed")
    finally:
        try:
            process.stdin.close()
        except Exception:
            pass


class MCPClientManager:
    """Threaded manager for outbound MCP ``stdio`` client sessions.

    Architectural rules (enforced by this implementation):

    1. **Pure sync UI, pure async daemon.** Public methods called from the
       console (``register_server``, ``start_server``, ``stop_server``,
       ``get_status``, ``get_all_external_tools``, ``shutdown``) never wait
       on the background event loop without a strict timeout, and
       ``register_server`` performs only synchronous file I/O.
    2. **Non-blocking start.** :meth:`start_server` schedules
       :meth:`_async_start_server` on :attr:`loop` via
       :func:`asyncio.run_coroutine_threadsafe` and returns immediately.
       The async path wraps connection setup in :func:`asyncio.wait_for`.
    3. **Aggressive stop.** :meth:`_async_stop_server` first tries a
       graceful close, then unconditionally ``terminate()`` / ``kill()``
       the captured subprocess so no zombie servers linger.
    4. **Process tracking.** Each running entry stores ``session``,
       ``exit_stack``, and ``process`` (``asyncio.subprocess.Process``)
       for direct kill access.
    5. **Bounded teardown.** :meth:`shutdown` iterates a snapshot of
       ``running_servers``, calls :meth:`stop_server` for each, then
       signals the loop to stop via ``loop.call_soon_threadsafe``.
    """

    DEFAULT_CONFIG_PATH = _DEFAULT_CONFIG_PATH

    def __init__(self, config_path: Union[str, Path, None] = None) -> None:
        self.config_path: Path = (
            Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        )
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._registered: Dict[str, MCPServerDefinition] = self._load_config()

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._loop_lock = threading.Lock()

        # State for every running server. Each entry has:
        #   {
        #       "session": ClientSession,
        #       "exit_stack": AsyncExitStack,
        #       "process": asyncio.subprocess.Process,
        #       "tools": list[mcp.types.Tool],
        #       "definition": MCPServerDefinition,
        #   }
        self.running_servers: Dict[str, Dict[str, Any]] = {}
        self._state_lock = threading.Lock()

    # -- config persistence (Rule 1: pure sync) ----------------------------

    def _load_config(self) -> Dict[str, MCPServerDefinition]:
        if not self.config_path.is_file():
            return {}
        try:
            with self.config_path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as exc:
            log.warning(
                "Ignoring malformed MCP config at %s: %s", self.config_path, exc
            )
            return {}
        if not isinstance(raw, list):
            log.warning("MCP config at %s is not a list; ignoring.", self.config_path)
            return {}
        out: Dict[str, MCPServerDefinition] = {}
        for entry in raw:
            try:
                defn = MCPServerDefinition.model_validate(entry)
            except Exception as exc:
                log.warning("Skipping invalid MCP server entry %r: %s", entry, exc)
                continue
            out[defn.name] = defn
        return out

    def _save_config(self) -> None:
        payload = [defn.model_dump() for defn in self._registered.values()]
        tmp_path = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        tmp_path.replace(self.config_path)

    # -- registration (Rule 1: pure sync, no event-loop touch) -------------

    def register_server(
        self,
        name: str,
        command: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> MCPServerDefinition:
        """Persist a server definition. Pure sync file I/O — no event loop.

        Existing entries with the same ``name`` are overwritten.
        """
        defn = MCPServerDefinition(
            name=name,
            command=command,
            args=list(args) if args else [],
            env=dict(env) if env else {},
        )
        self._registered[name] = defn
        self._save_config()
        return defn

    def delete_server(self, name: str) -> bool:
        """Remove a registered server from the config file.

        If the server is currently running, it is stopped (with the same
        bounded timeout as :meth:`stop_server`) before removal.
        """
        if name not in self._registered:
            return False
        with self._state_lock:
            running = name in self.running_servers
        if running:
            self.stop_server(name)
        del self._registered[name]
        self._save_config()
        return True

    def list_registered(self) -> List[MCPServerDefinition]:
        """Return all registered server definitions."""
        return list(self._registered.values())

    # -- background loop ---------------------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._loop_lock:
            if (
                self.loop is not None
                and self._thread is not None
                and self._thread.is_alive()
            ):
                return self.loop
            ready = threading.Event()
            container: List[asyncio.AbstractEventLoop] = []

            def runner() -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                container.append(loop)
                ready.set()
                try:
                    loop.run_forever()
                finally:
                    try:
                        pending = asyncio.all_tasks(loop)
                        for task in pending:
                            task.cancel()
                        if pending:
                            loop.run_until_complete(
                                asyncio.gather(*pending, return_exceptions=True)
                            )
                    finally:
                        loop.close()

            self._thread = threading.Thread(
                target=runner, name="MCPClientManager-loop", daemon=True
            )
            self._thread.start()
            ready.wait()
            self.loop = container[0]
            return self.loop

    # -- start (Rule 2: non-blocking) --------------------------------------

    def start_server(self, name: str) -> str:
        """Schedule the connection on the background loop and return now.

        Returns a one-line status string suitable for the console. The
        actual stdio handshake happens on the daemon thread, bounded by
        :data:`_INIT_TIMEOUT_SECONDS`. Use :meth:`get_status` to confirm
        the server has finished initialising.
        """
        if name not in self._registered:
            return f"Server {name!r} is not registered."
        with self._state_lock:
            if name in self.running_servers:
                tool_count = len(self.running_servers[name].get("tools", []))
                return f"Server {name!r} is already running ({tool_count} tools)."
        loop = self._ensure_loop()
        asyncio.run_coroutine_threadsafe(self._async_start_server(name), loop)
        return f"Starting MCP server {name!r} in background…"

    async def _async_start_server(self, name: str) -> None:
        """Spawn the subprocess, bridge stdio, run the MCP handshake.

        Bounded by :data:`_INIT_TIMEOUT_SECONDS` so a wedged server cannot
        strand the daemon. On any failure path the subprocess is
        force-killed before the coroutine returns.
        """
        definition = self._registered.get(name)
        if definition is None:
            log.warning("MCP server %r vanished from config before start", name)
            return

        # ---- Step 1: spawn the subprocess ourselves so we own the handle.
        try:
            spawn_env: Optional[Dict[str, str]] = None
            if definition.env:
                spawn_env = {**os.environ, **definition.env}
            process = await asyncio.create_subprocess_exec(
                definition.command,
                *definition.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                env=spawn_env,
            )
        except Exception as exc:
            log.error("Failed to spawn MCP server %r: %s", name, exc)
            return

        # ---- Step 2: bridge stdio with anyio in-memory channels.
        read_writer, read_reader = anyio.create_memory_object_stream[Any](
            max_buffer_size=0
        )
        write_writer, write_reader = anyio.create_memory_object_stream[Any](
            max_buffer_size=0
        )
        out_task = asyncio.create_task(_stdout_to_session_stream(process, read_writer))
        in_task = asyncio.create_task(_session_stream_to_stdin(process, write_reader))

        exit_stack = AsyncExitStack()

        async def _stop_pumps() -> None:
            for task in (out_task, in_task):
                task.cancel()
            await asyncio.gather(out_task, in_task, return_exceptions=True)
            for stream in (read_writer, write_writer):
                try:
                    await stream.aclose()
                except Exception:
                    pass

        exit_stack.push_async_callback(_stop_pumps)

        # ---- Step 3: run the MCP handshake under a strict timeout.
        try:
            session = await exit_stack.enter_async_context(
                ClientSession(read_reader, write_writer)
            )
            await asyncio.wait_for(session.initialize(), timeout=_INIT_TIMEOUT_SECONDS)
            listing = await asyncio.wait_for(
                session.list_tools(), timeout=_INIT_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            log.error(
                "MCP server %r did not finish handshake within %.1fs; aborting",
                name,
                _INIT_TIMEOUT_SECONDS,
            )
            await self._cleanup_after_failed_start(exit_stack, process)
            return
        except Exception as exc:
            log.error("MCP server %r failed during init: %s", name, exc)
            await self._cleanup_after_failed_start(exit_stack, process)
            return

        with self._state_lock:
            self.running_servers[name] = {
                "session": session,
                "exit_stack": exit_stack,
                "process": process,
                "tools": list(listing.tools),
                "definition": definition,
            }
        log.info(
            "MCP server %r ready (pid=%d, tools=%d)",
            name,
            process.pid,
            len(listing.tools),
        )

    async def _cleanup_after_failed_start(
        self,
        exit_stack: AsyncExitStack,
        process: asyncio.subprocess.Process,
    ) -> None:
        """Best-effort teardown when init times out or raises."""
        try:
            await asyncio.wait_for(exit_stack.aclose(), timeout=2.0)
        except Exception:
            pass
        await self._force_kill(process)

    @staticmethod
    async def _force_kill(process: asyncio.subprocess.Process) -> None:
        """terminate → 1s wait → kill → 1s wait. Survives all races."""
        if process.returncode is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
            return
        except asyncio.TimeoutError:
            pass
        try:
            process.kill()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            log.error(
                "Subprocess pid=%d refused SIGKILL; leaving as orphan",
                process.pid,
            )

    # -- stop (Rule 3: aggressive termination) -----------------------------

    def stop_server(self, name: str, *, timeout: float = _STOP_TIMEOUT_SECONDS) -> str:
        """Stop ``name`` synchronously, bounded by ``timeout`` seconds.

        Internally schedules :meth:`_async_stop_server` on the background
        loop and waits with a strict timeout — never indefinitely.
        """
        with self._state_lock:
            if name not in self.running_servers:
                return f"Server {name!r} is not running."
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._async_stop_server(name), loop)
        try:
            future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            log.warning(
                "stop_server(%r) exceeded %.1fs; subprocess may still be terminating",
                name,
                timeout,
            )
            return (
                f"Stop of {name!r} did not finish in {timeout:.1f}s — "
                "the subprocess may still be terminating."
            )
        except Exception as exc:
            log.exception("Unexpected error stopping MCP server %r", name)
            return f"Error stopping {name!r}: {exc}"
        return f"Stopped MCP server {name!r}."

    async def _async_stop_server(self, name: str) -> None:
        """Graceful close → fall through → terminate → kill. In that order.

        Implements Rule 3 verbatim. Any exception thrown by the graceful
        path is swallowed; subprocess termination is mandatory.
        """
        # Step 1: retrieve the state (and remove it so re-entry is safe).
        with self._state_lock:
            state = self.running_servers.pop(name, None)
        if state is None:
            return

        exit_stack: AsyncExitStack = state["exit_stack"]
        process: asyncio.subprocess.Process = state["process"]

        # Step 2: graceful closure with a 3s ceiling.
        try:
            await asyncio.wait_for(exit_stack.aclose(), timeout=3.0)
        # Step 3: catch broadly — graceful close MUST NOT block force kill.
        except asyncio.TimeoutError:
            log.warning("Graceful close of MCP server %r timed out; forcing kill", name)
        except Exception as exc:
            log.warning(
                "Graceful close of MCP server %r raised %s; forcing kill",
                name,
                exc,
            )

        # Step 4: force-kill the subprocess no matter what.
        await self._force_kill(process)
        log.info("MCP server %r stopped", name)

    # -- introspection -----------------------------------------------------

    def get_status(self) -> List[Dict[str, Any]]:
        """Snapshot of every connected server."""
        with self._state_lock:
            snapshot = list(self.running_servers.items())
        out: List[Dict[str, Any]] = []
        for name, state in snapshot:
            definition: MCPServerDefinition = state["definition"]
            process: asyncio.subprocess.Process = state["process"]
            out.append(
                {
                    "name": name,
                    "command": definition.command,
                    "args": list(definition.args),
                    "tools": len(state.get("tools", [])),
                    "pid": process.pid,
                }
            )
        return out

    def get_all_external_tools(self) -> List[ToolSpec]:
        """Return every tool exposed by every connected MCP server.

        Tool names are namespaced as ``<server>__<tool>`` so external
        tools never collide with Wintermute's internal cartridge tools.
        """
        out: List[ToolSpec] = []
        with self._state_lock:
            snapshot = [
                (name, list(state.get("tools", [])))
                for name, state in self.running_servers.items()
            ]
        for name, tools in snapshot:
            for tool in tools:
                description = getattr(tool, "description", "") or ""
                input_schema = cast(JSONObject, getattr(tool, "inputSchema", {}) or {})
                out.append(
                    ToolSpec(
                        name=f"{name}__{tool.name}",
                        description=description,
                        input_schema=input_schema,
                        output_schema={},
                    )
                )
        return out

    # -- shutdown (Rule 5) -------------------------------------------------

    def shutdown(self, *, timeout: float = _STOP_TIMEOUT_SECONDS) -> None:
        """Stop every running server, then signal the daemon loop to stop.

        Iterates a copy of ``running_servers``' keys per Rule 5 so the
        underlying dict can be mutated by the in-flight stop coroutines
        without raising.
        """
        with self._state_lock:
            names = list(self.running_servers.keys())
        for name in names:
            try:
                self.stop_server(name, timeout=timeout)
            except Exception:
                log.exception("shutdown: failed to stop %r", name)

        # Brief pause to let the loop finalise any cancellation callbacks.
        time.sleep(0.1)

        with self._loop_lock:
            loop = self.loop
            thread = self._thread
            self.loop = None
            self._thread = None
        if loop is not None and thread is not None and thread.is_alive():
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=timeout)


__all__ = [
    "MCPClientManager",
    "MCPRuntime",
    "MCPServerDefinition",
]
