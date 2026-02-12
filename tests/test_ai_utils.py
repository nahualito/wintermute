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

import json
from unittest.mock import patch

import pytest

from wintermute.ai.json_types import JSONObject
from wintermute.ai.tools_runtime import Tool, ToolRegistry
from wintermute.ai.utils.hardware import enrich_processor
from wintermute.hardware import Architecture, Processor


def test_tool_registry() -> None:
    registry = ToolRegistry()

    # FIX: Use JSONObject type hint to match Tool.handler signature
    def my_handler(args: JSONObject) -> JSONObject:
        # We assume args['x'] exists and is an int for this test
        val = args.get("x")
        if isinstance(val, int):
            return {"result": val * 2}
        return {"result": 0}

    tool = Tool(
        name="doubler",
        input_schema={"x": "int"},
        output_schema={"result": "int"},
        handler=my_handler,
    )

    registry.register(tool)
    assert "doubler" in registry._tools

    result = registry.call("doubler", {"x": 21})
    assert result == {"result": 42}


def test_enrich_processor_success() -> None:
    """Test that enrich_processor parses valid JSON from LLM."""

    # Mock Processor
    initial_proc = Processor(processor="GenericChip")

    # Mock LLM Response (JSON)
    llm_response_json = json.dumps(
        {
            "processor": "GenericChip",
            "description": "AI Enhanced Description",
            "architecture": {"core": "AI-Core", "cpu_cores": 4},
        }
    )

    with patch(
        "wintermute.ai.utils.hardware.simple_chat", return_value=llm_response_json
    ) as mock_chat:
        enriched = enrich_processor(initial_proc)

        # Verify simple_chat was called
        mock_chat.assert_called_once()

        # Verify object was updated
        assert enriched.description == "AI Enhanced Description"

        # FIX: Handle Union[Architecture, Dict, None] for mypy
        assert enriched.architecture is not None

        if isinstance(enriched.architecture, dict):
            assert enriched.architecture["core"] == "AI-Core"
        elif isinstance(enriched.architecture, Architecture):
            assert enriched.architecture.core == "AI-Core"
        else:
            pytest.fail("Architecture is of unexpected type")


def test_enrich_processor_failure() -> None:
    """Test graceful failure on bad JSON."""
    initial_proc = Processor(processor="GenericChip")

    with patch("wintermute.ai.utils.hardware.simple_chat", return_value="NOT JSON"):
        enriched = enrich_processor(initial_proc)

        # Should return original processor without crashing
        assert enriched.processor == "GenericChip"
        assert enriched.description is None
