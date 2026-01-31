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

import atexit
import logging
import subprocess
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Tuple

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

log = logging.getLogger(__name__)


class SurgeonController:
    def __init__(self, mcp_script_path: str, surgeon_root: str) -> None:
        self.mcp_script = Path(mcp_script_path)
        self.surgeon_root = Path(surgeon_root)
        # [FIX] Add type parameter [str] to Popen for text mode
        self._process: Optional[subprocess.Popen[str]] = None

        # Ensure cleanup on script exit
        atexit.register(self.stop)

    def start(self) -> bool:
        """
        Spawns the MCP server in a non-blocking subprocess.
        """
        if self._process and self._process.poll() is None:
            log.warning("SURGEON MCP server is already running.")
            return True

        if not self.mcp_script.exists():
            log.error(f"MCP Script not found at: {self.mcp_script}")
            return False

        cmd = [sys.executable, str(self.mcp_script)]

        env = {
            "SURGEON_ROOT": str(self.surgeon_root),
            **dict(sys.modules["os"].environ),  # Inherit current env vars
        }

        try:
            log.info("Starting SURGEON MCP Server...")

            # Popen is non-blocking.
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                bufsize=0,
            )

            time.sleep(0.5)
            if self._process.poll() is not None:
                # If it crashed immediately, read stderr
                _, err = self._process.communicate()
                log.error(f"SURGEON MCP failed to start: {err}")
                return False

            log.info(f"SURGEON MCP Server started (PID: {self._process.pid})")
            return True

        except Exception as e:
            log.error(f"Failed to spawn SURGEON MCP: {e}")
            return False

    # [FIX] Add return type annotation
    def get_stdio(self) -> Tuple[Optional[IO[str]], Optional[IO[str]]]:
        """
        Returns the stdin/stdout pipes to be used by the MCP Client.
        """
        if not self._process:
            raise RuntimeError("Process not running. Call start() first.")
        return self._process.stdin, self._process.stdout

    # [FIX] Add return type annotation
    def stop(self) -> None:
        """
        Terminates the MCP server gracefully.
        """
        if self._process and self._process.poll() is None:
            log.info("Stopping SURGEON MCP Server...")
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
            log.info("SURGEON MCP Server stopped.")


class SurgeonBackend:
    # [FIX] Add return type annotation
    def __init__(self, surgeon_root: str) -> None:
        current_dir = Path(__file__).parent
        server_script = current_dir / "server.py"

        self.controller = SurgeonController(str(server_script), surgeon_root)
        self.session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None

    async def start(self) -> None:
        """Starts the subprocess and initializes the MCP session."""
        if not self.controller.start():
            raise RuntimeError("Failed to start SURGEON MCP server.")

        server_params = StdioServerParameters(
            command="python3",
            args=[str(self.controller.mcp_script)],
            env={"SURGEON_ROOT": str(self.controller.surgeon_root)},
        )

        self._exit_stack = AsyncExitStack()

        try:
            read, write = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            self.session = await self._exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            await self.session.initialize()
            log.info("Connected to SURGEON MCP Session.")

        except Exception as e:
            log.error(f"Failed to connect MCP session: {e}")
            await self.stop()

    # [FIX] Add return type annotation
    async def stop(self) -> None:
        if self._exit_stack:
            await self._exit_stack.aclose()
        self.controller.stop()

    async def get_ai_tools(self) -> List[Dict[str, Any]]:
        """
        Fetches tools from MCP and converts them to OpenAI/Wintermute format.
        """
        if not self.session:
            return []

        try:
            mcp_tools = await self.session.list_tools()
            openai_tools = []

            for tool in mcp_tools.tools:
                openai_tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.inputSchema,
                        },
                    }
                )

            return openai_tools
        except Exception as e:
            log.error(f"Failed to list tools from SURGEON MCP: {e}")
            return []

    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """
        Executes a tool on the remote MCP server.
        """
        if not self.session:
            return "Error: SURGEON Backend not connected."

        try:
            result = await self.session.call_tool(tool_name, arguments)
            return "\n".join([c.text for c in result.content if c.type == "text"])
        except Exception as e:
            log.error(f"SURGEON Execution Error: {e}")
            return f"Error executing {tool_name}: {str(e)}"
