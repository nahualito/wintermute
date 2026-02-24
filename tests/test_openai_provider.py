# -*- coding: utf-8 -*-
from unittest.mock import MagicMock, patch

import pytest

from wintermute.ai.providers.openai_provider import OpenAIProvider
from wintermute.ai.types import ChatRequest, Message, ToolSpec


@pytest.fixture
def provider() -> OpenAIProvider:
    return OpenAIProvider(api_key="sk-test")


def test_openai_chat_formatting(provider: OpenAIProvider) -> None:
    mock_choice = MagicMock()
    mock_choice.message.content = "OpenAI response"
    mock_choice.message.tool_calls = None

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage.prompt_tokens = 15
    mock_response.usage.completion_tokens = 10

    with patch("litellm.completion", return_value=mock_response) as mock_completion:
        req = ChatRequest(
            messages=[Message(role="user", content="Hello OpenAI")], model="gpt-4o"
        )
        response = provider.chat(req)

        args, kwargs = mock_completion.call_args
        assert kwargs["model"] == "gpt-4o"
        assert response.content == "OpenAI response"
        assert response.prompt_tokens == 15


def test_openai_tool_calls(provider: OpenAIProvider) -> None:
    mock_tool_call = MagicMock()
    mock_tool_call.id = "call_openai"
    mock_tool_call.function.name = "get_secret"
    mock_tool_call.function.arguments = {"key": "top_secret"}

    mock_choice = MagicMock()
    mock_choice.message.content = None
    mock_choice.message.tool_calls = [mock_tool_call]

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    with patch("litellm.completion", return_value=mock_response):
        req = ChatRequest(
            messages=[Message(role="user", content="What is the secret?")],
            tools=[
                ToolSpec(name="get_secret", description="gets secret", input_schema={})
            ],
        )
        response = provider.chat(req)

        assert response.tool_calls is not None
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].name == "get_secret"
