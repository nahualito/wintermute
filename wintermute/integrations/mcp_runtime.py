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
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional, cast

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Wintermute imports
from wintermute.ai.json_types import JSONObject
from wintermute.ai.tools_runtime import Tool
from wintermute.ai.tools_runtime import tools as global_registry


class MCPRuntime:
    """
    Manages the lifecycle of an MCP connection and registers its tools
    into the Wintermute ToolRegistry.
    """

    def __init__(
        self, command: str, args: List[str], env: Optional[Dict[str, str]] = None
    ) -> None:
        self.server_params = StdioServerParameters(command=command, args=args, env=env)
        self.session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None

    async def initialize(self) -> None:
        """Connects to MCP and registers tools into Wintermute's global registry."""
        self._exit_stack = AsyncExitStack()

        # 1. Connect
        # We explicitly assert to satisfy mypy that _exit_stack is initialized
        assert self._exit_stack is not None

        read, write = await self._exit_stack.enter_async_context(
            stdio_client(self.server_params)
        )
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
