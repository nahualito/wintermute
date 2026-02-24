# -*- coding: utf-8 -*-
from unittest.mock import MagicMock, patch

import pytest

from wintermute.ai.providers.groq_provider import GroqProvider
from wintermute.ai.types import ChatRequest, Message


@pytest.fixture
def provider() -> GroqProvider:
    return GroqProvider(api_key="gsk_test")


def test_groq_chat_formatting(provider: GroqProvider) -> None:
    mock_choice = MagicMock()
    mock_choice.message.content = "Groq response"
    mock_choice.message.tool_calls = None

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage.prompt_tokens = 20
    mock_response.usage.completion_tokens = 15

    with patch("litellm.completion", return_value=mock_response) as mock_completion:
        req = ChatRequest(
            messages=[Message(role="user", content="Hello Groq")],
            model="groq/llama-3.3-70b-versatile",
        )
        response = provider.chat(req)

        args, kwargs = mock_completion.call_args
        assert kwargs["model"] == "groq/llama-3.3-70b-versatile"
        assert response.content == "Groq response"
        assert response.completion_tokens == 15


def test_groq_prefix_handling(provider: GroqProvider) -> None:
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "OK"

    with patch("litellm.completion", return_value=mock_response) as mock_completion:
        # Request without prefix
        req = ChatRequest(
            messages=[Message(role="user", content="Hi")], model="llama-3.1-8b-instant"
        )
        provider.chat(req)

        args, kwargs = mock_completion.call_args
        assert kwargs["model"] == "groq/llama-3.1-8b-instant"
