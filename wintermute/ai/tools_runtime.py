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

# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Protocol, runtime_checkable

from ..ai.json_types import JSONObject
from ..ai.types import ToolSpec

log = logging.getLogger(__name__)

# --- Existing Tool Definitions ---


@dataclass(frozen=True)
class Tool:
    name: str
    input_schema: JSONObject
    output_schema: JSONObject
    handler: Callable[[JSONObject], JSONObject]
    description: str = ""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def call(self, name: str, args: JSONObject) -> JSONObject:
        if name not in self._tools:
            raise KeyError(f"Tool {name} not found")
        tool = self._tools[name]
        return tool.handler(args)

    def get_definitions(self) -> List[Dict[str, Any]]:
        """Convert registered tools to OpenAI-compatible function definitions."""
        definitions = []
        for name, tool in self._tools.items():
            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema,
                    },
                }
            )
        return definitions


# Global registry instance
tools = ToolRegistry()


def spec_from_tool(tool: Tool, description: str = "") -> ToolSpec:
    return ToolSpec(
        name=tool.name,
        description=description or tool.description,
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
    )


# --- New Runtime for MCP Integration ---


@runtime_checkable
class ToolBackend(Protocol):
    """Protocol defining what a dynamic tool backend must implement."""

    async def get_ai_tools(self) -> List[Dict[str, Any]]: ...
    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str: ...


class ToolsRuntime:
    """
    Orchestrates tool execution across local static tools (ToolRegistry)
    and dynamic backends (MCP Servers like Surgeon).
    """

    def __init__(self) -> None:
        self.dynamic_backends: List[ToolBackend] = []

    def register_backend(self, backend: ToolBackend) -> None:
        """Register a dynamic backend (e.g., SurgeonBackend)."""
        self.dynamic_backends.append(backend)

    async def get_all_tools(self) -> List[Dict[str, Any]]:
        """Combine static local tools with dynamic backend tools."""
        # 1. Start with local tools from the global registry
        all_tools = tools.get_definitions()

        # 2. Fetch tools from dynamic backends
        for backend in self.dynamic_backends:
            try:
                backend_tools = await backend.get_ai_tools()
                all_tools.extend(backend_tools)
            except Exception as e:
                log.error(f"Failed to fetch tools from backend {backend}: {e}")

        return all_tools

    async def run_tool(self, name: str, args: Dict[str, Any]) -> str:
        """
        Execute a tool by name. Checks dynamic backends first, then local registry.
        """
        log.info(f"AI requested execution of tool: {name}")

        # 1. Check Dynamic Backends (MCP)
        for backend in self.dynamic_backends:
            try:
                # Optimization: We assume backend names are unique or check quickly
                # Ideally, we'd cache the map of tool_name -> backend
                known_tools = await backend.get_ai_tools()
                if any(t["function"]["name"] == name for t in known_tools):
                    return await backend.execute_tool(name, args)
            except Exception as e:
                log.error(f"Error checking backend {backend}: {e}")

        # 2. Fallback to Local Tools
        return await self._run_local_tool(name, args)

    async def _run_local_tool(self, name: str, args: Dict[str, Any]) -> str:
        """
        Executes a tool from the local ToolRegistry.
        """
        try:
            result = tools.call(name, args)
            return str(result)
        except KeyError:
            error_msg = (
                f"Tool '{name}' not found in local registry or connected backends."
            )
            log.warning(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Error executing local tool '{name}': {str(e)}"
            log.error(error_msg)
            return error_msg
