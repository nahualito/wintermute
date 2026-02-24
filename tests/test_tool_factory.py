# -*- coding: utf-8 -*-
from typing import Any, Dict, List, cast

from wintermute.ai.utils.tool_factory import function_to_tool, register_tools


def sample_func(x: int, y: str = "default") -> str:
    """A sample function for testing."""
    return f"{y}: {x}"


def test_function_to_tool_schema_generation() -> None:
    tool = function_to_tool(sample_func)

    assert tool.name == "sample_func"
    assert tool.description == "A sample function for testing."

    # Check input schema
    input_schema = cast(Dict[str, Any], tool.input_schema)
    properties = cast(Dict[str, Any], input_schema["properties"])
    assert "x" in properties
    assert properties["x"]["type"] == "integer"
    assert "y" in properties
    assert properties["y"]["type"] == "string"
    assert properties["y"]["default"] == "default"
    assert "x" in cast(List[str], input_schema["required"])

    # Check output schema
    output_schema = cast(Dict[str, Any], tool.output_schema)
    assert "result" in cast(Dict[str, Any], output_schema["properties"])
    assert (
        cast(Dict[str, Any], output_schema["properties"])["result"]["type"] == "string"
    )


def test_tool_execution_handler() -> None:
    tool = function_to_tool(sample_func)
    handler = tool.handler

    result = handler({"x": 42, "y": "hello"})
    assert result == {"result": "hello: 42"}

    # Test with default value
    result_default = handler({"x": 10})
    assert result_default == {"result": "default: 10"}


def test_register_tools() -> None:
    def another_func(a: float) -> float:
        return a * 2

    tool_list = register_tools([sample_func, another_func])

    assert len(tool_list) == 2
    assert tool_list[0].name == "sample_func"
    assert tool_list[1].name == "another_func"
