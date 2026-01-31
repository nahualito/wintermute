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

from unittest.mock import MagicMock, patch

import pytest

from wintermute.ai.providers.bedrock_provider import BedrockProvider
from wintermute.ai.types import ChatRequest, Message, ToolSpec


@pytest.fixture
def provider() -> BedrockProvider:
    return BedrockProvider(region="us-east-1")


def test_bedrock_converse_formatting(provider: BedrockProvider) -> None:
    """Test mapping of Wintermute messages to Bedrock Converse format."""

    # Mock boto3 client
    mock_boto = MagicMock()

    # Mock response
    mock_response = {
        "output": {"message": {"content": [{"text": "Hello user"}]}},
        "usage": {"inputTokens": 10, "outputTokens": 5},
    }
    mock_boto.converse.return_value = mock_response

    with patch("boto3.client", return_value=mock_boto):
        # Create a complex request
        req = ChatRequest(
            messages=[
                Message(role="system", content="Be helpful"),
                Message(role="user", content="Hi"),
            ],
            model="anthropic.claude-3",
            tools=[
                ToolSpec(
                    name="get_weather",
                    description="fetches weather",
                    input_schema={"type": "object"},
                )
            ],
        )

        response = provider.chat(req)

        # Verify arguments passed to boto3
        args, kwargs = mock_boto.converse.call_args

        # 1. Check System Prompt extraction
        assert kwargs["system"] == [{"text": "Be helpful"}]

        # 2. Check Message formatting
        assert kwargs["messages"] == [{"role": "user", "content": [{"text": "Hi"}]}]

        # 3. Check Tool Config
        assert "toolConfig" in kwargs
        assert kwargs["toolConfig"]["tools"][0]["toolSpec"]["name"] == "get_weather"

        # 4. Check Response parsing
        assert response.content == "Hello user"


def test_bedrock_tool_call_parsing(provider: BedrockProvider) -> None:
    """Test parsing of toolUse blocks from Bedrock response."""

    mock_boto = MagicMock()
    mock_response = {
        "output": {
            "message": {
                "content": [
                    {"text": "Thinking..."},
                    {
                        "toolUse": {
                            "toolUseId": "call_123",
                            "name": "calc",
                            "input": {"x": 1},
                        }
                    },
                ]
            }
        }
    }
    mock_boto.converse.return_value = mock_response

    with patch("boto3.client", return_value=mock_boto):
        req = ChatRequest(messages=[Message(role="user", content="calc 1")])
        resp = provider.chat(req)

        assert "Thinking..." in resp.content
        assert resp.tool_calls is not None
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].id == "call_123"
        assert resp.tool_calls[0].name == "calc"
        assert resp.tool_calls[0].arguments == {"x": 1}
