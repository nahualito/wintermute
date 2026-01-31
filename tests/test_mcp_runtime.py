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

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wintermute.ai.tools_runtime import tools as global_registry
from wintermute.integrations.mcp_runtime import MCPRuntime


@pytest.mark.asyncio
async def test_mcp_initialization_and_registration() -> None:
    # Mock data
    mock_tool_list = MagicMock()
    mock_tool_list.tools = [MagicMock(name="test_tool", inputSchema={"type": "object"})]
    mock_tool_list.tools[0].name = "test_tool"

    # Mock Session and Context Managers
    mock_session = AsyncMock()
    mock_session.initialize.return_value = None
    mock_session.list_tools.return_value = mock_tool_list

    # CRITICAL FIX: Ensure the context manager returns the SAME mock object
    # When await self._exit_stack.enter_async_context(ClientSession(...)) is called,
    # it awaits ClientSession().__aenter__(). We must return mock_session itself.
    mock_session.__aenter__.return_value = mock_session

    # Patch the dependencies
    with (
        patch("wintermute.integrations.mcp_runtime.stdio_client") as mock_stdio,
        patch(
            "wintermute.integrations.mcp_runtime.ClientSession",
            return_value=mock_session,
        ),
    ):
        # Setup mocks for context managers (stdio_client)
        # stdio_client() returns a context manager, __aenter__ returns (read, write)
        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())

        # Initialize Runtime
        runtime = MCPRuntime(command="ls", args=["-la"])
        await runtime.initialize()

        # Assertions
        assert runtime.session is not None
        # This assert failed previously because runtime.session was a different mock
        assert runtime.session is mock_session
        mock_session.initialize.assert_awaited_once()
        mock_session.list_tools.assert_awaited_once()

        # Check if tool was registered in Wintermute global registry
        assert "test_tool" in global_registry._tools

        # Clean up
        await runtime.shutdown()


@pytest.mark.asyncio
async def test_mcp_tool_execution() -> None:
    # Setup Runtime with a mock session already injected
    runtime = MCPRuntime("echo", [])
    mock_session = AsyncMock()
    runtime.session = mock_session

    # Mock response from MCP server
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = "Hello World"

    mock_result = MagicMock()
    mock_result.content = [mock_content]
    mock_session.call_tool.return_value = mock_result

    # Execute
    result = await runtime._execute_mcp_tool("test_tool", {"arg": "val"})

    # Verify
    mock_session.call_tool.assert_awaited_with("test_tool", {"arg": "val"})
    assert result["output"] == "Hello World"
