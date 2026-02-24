# -*- coding: utf-8 -*-
from unittest.mock import AsyncMock

import pytest

from wintermute.ai.json_types import JSONObject
from wintermute.ai.tools_runtime import Tool, ToolRegistry, ToolsRuntime, tools


def test_tool_registry_call() -> None:
    registry = ToolRegistry()

    def mock_handler(args: JSONObject) -> JSONObject:
        return {"processed": args["data"]}

    tool = Tool(
        name="test_tool",
        input_schema={},
        output_schema={},
        handler=mock_handler,
        description="test desc",
    )
    registry.register(tool)

    result = registry.call("test_tool", {"data": "val"})
    assert result == {"processed": "val"}

    with pytest.raises(KeyError):
        registry.call("nonexistent", {})


def test_tool_registry_get_definitions() -> None:
    registry = ToolRegistry()
    tool = Tool(
        name="test_tool",
        input_schema={"type": "object"},
        output_schema={},
        handler=lambda x: x,
        description="test desc",
    )
    registry.register(tool)

    defs = registry.get_definitions()
    assert len(defs) == 1
    assert defs[0]["function"]["name"] == "test_tool"
    assert defs[0]["function"]["parameters"] == {"type": "object"}


@pytest.mark.asyncio
async def test_tools_runtime_combined_tools() -> None:
    runtime = ToolsRuntime()

    # Mock dynamic backend
    mock_backend = AsyncMock()
    mock_backend.get_ai_tools.return_value = [{"function": {"name": "dynamic_tool"}}]
    runtime.register_backend(mock_backend)

    # We use the global 'tools' registry which might have other tools,
    # but we can check if our dynamic one is included.
    all_tools = await runtime.get_all_tools()
    assert any(t["function"]["name"] == "dynamic_tool" for t in all_tools)


@pytest.mark.asyncio
async def test_tools_runtime_run_tool_dynamic() -> None:
    runtime = ToolsRuntime()
    mock_backend = AsyncMock()
    mock_backend.get_ai_tools.return_value = [{"function": {"name": "dynamic_tool"}}]
    mock_backend.execute_tool.return_value = "dynamic_result"
    runtime.register_backend(mock_backend)

    result = await runtime.run_tool("dynamic_tool", {"arg": 1})
    assert result == "dynamic_result"
    mock_backend.execute_tool.assert_called_once_with("dynamic_tool", {"arg": 1})


@pytest.mark.asyncio
async def test_tools_runtime_run_tool_local() -> None:
    runtime = ToolsRuntime()

    # Register a local tool in the global registry for testing
    def local_handler(args: JSONObject) -> JSONObject:
        return {"res": "ok"}

    tool = Tool("local_test", {}, {}, local_handler, "desc")
    tools.register(tool)

    result = await runtime.run_tool("local_test", {})
    assert "ok" in result


@pytest.mark.asyncio
async def test_tools_runtime_run_tool_not_found() -> None:
    runtime = ToolsRuntime()
    result = await runtime.run_tool("missing_tool", {})
    assert "not found" in result
