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

"""Phase 1 transport-abstraction tests for MCPRuntime.

These exercise the new config-dict constructor with both ``stdio`` and
``sse`` transports, verifying:

* the correct underlying MCP client (``stdio_client`` vs ``sse_client``) is
  instantiated based on ``config["type"]``;
* tool listings returned by the mocked session are registered in the
  Wintermute global registry;
* invalid configs raise during construction (no event-loop work).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wintermute.ai.tools_runtime import tools as global_registry
from wintermute.integrations.mcp_runtime import MCPRuntime


def _make_mock_session(tool_names: list[str]) -> AsyncMock:
    """Build an AsyncMock ClientSession whose list_tools() returns ``tool_names``."""
    tools = []
    for tname in tool_names:
        t = MagicMock(inputSchema={"type": "object"})
        t.name = tname
        tools.append(t)
    tool_list = MagicMock()
    tool_list.tools = tools

    session = AsyncMock()
    session.initialize.return_value = None
    session.list_tools.return_value = tool_list
    # ClientSession is entered as an async context manager; __aenter__ must
    # return the session itself so MCPRuntime can store it.
    session.__aenter__.return_value = session
    return session


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


def test_stdio_config_construction() -> None:
    rt = MCPRuntime({"type": "stdio", "command": "ls", "args": ["-la"]})
    assert rt.transport == "stdio"
    assert rt.config["command"] == "ls"


def test_sse_config_construction() -> None:
    rt = MCPRuntime({"type": "sse", "url": "http://node-7.local:9000/sse"})
    assert rt.transport == "sse"
    assert rt.config["url"] == "http://node-7.local:9000/sse"


def test_legacy_keyword_form_still_works() -> None:
    rt = MCPRuntime(command="echo", args=["hi"])
    assert rt.transport == "stdio"
    assert rt.config["command"] == "echo"
    assert rt.config["args"] == ["hi"]


def test_unknown_transport_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported MCP transport"):
        MCPRuntime({"type": "websocket", "url": "ws://x"})


def test_stdio_missing_command_rejected() -> None:
    with pytest.raises(ValueError, match="stdio MCP config requires"):
        MCPRuntime({"type": "stdio"})


def test_sse_missing_url_rejected() -> None:
    with pytest.raises(ValueError, match="sse MCP config requires"):
        MCPRuntime({"type": "sse"})


def test_no_config_and_no_command_rejected() -> None:
    with pytest.raises(ValueError, match="requires either"):
        MCPRuntime()


# ---------------------------------------------------------------------------
# initialize() — transport-specific client selection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initialize_uses_stdio_client_for_stdio_config() -> None:
    session = _make_mock_session(["stdio_only_tool"])

    with (
        patch("wintermute.integrations.mcp_runtime.stdio_client") as mock_stdio,
        patch("wintermute.integrations.mcp_runtime.sse_client") as mock_sse,
        patch(
            "wintermute.integrations.mcp_runtime.ClientSession",
            return_value=session,
        ),
    ):
        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())

        rt = MCPRuntime(
            {"type": "stdio", "command": "ls", "args": ["-la"], "env": {"X": "1"}}
        )
        await rt.initialize()

        mock_stdio.assert_called_once()
        mock_sse.assert_not_called()
        # The StdioServerParameters built inside initialize() must reflect the config.
        params = mock_stdio.call_args.args[0]
        assert params.command == "ls"
        assert params.args == ["-la"]
        assert params.env == {"X": "1"}

        session.initialize.assert_awaited_once()
        session.list_tools.assert_awaited_once()
        assert "stdio_only_tool" in global_registry._tools

        await rt.shutdown()


@pytest.mark.asyncio
async def test_initialize_uses_sse_client_for_sse_config() -> None:
    session = _make_mock_session(["sse_remote_tool"])

    with (
        patch("wintermute.integrations.mcp_runtime.stdio_client") as mock_stdio,
        patch("wintermute.integrations.mcp_runtime.sse_client") as mock_sse,
        patch(
            "wintermute.integrations.mcp_runtime.ClientSession",
            return_value=session,
        ),
    ):
        mock_sse.return_value.__aenter__.return_value = (MagicMock(), MagicMock())

        rt = MCPRuntime(
            {
                "type": "sse",
                "url": "http://10.0.0.7:9000/sse",
                "headers": {"Authorization": "Bearer xyz"},
            }
        )
        await rt.initialize()

        mock_sse.assert_called_once_with(
            url="http://10.0.0.7:9000/sse",
            headers={"Authorization": "Bearer xyz"},
        )
        mock_stdio.assert_not_called()

        session.initialize.assert_awaited_once()
        session.list_tools.assert_awaited_once()
        assert "sse_remote_tool" in global_registry._tools

        await rt.shutdown()
