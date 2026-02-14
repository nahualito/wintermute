from unittest.mock import MagicMock

import pytest

from wintermute.ai.retry import with_retries


def test_with_retries_success() -> None:
    mock_fn = MagicMock(return_value="success")
    result = with_retries(mock_fn, attempts=3, backoff_sec=0.01)
    assert result == "success"
    assert mock_fn.call_count == 1


def test_with_retries_failure_then_success() -> None:
    mock_fn = MagicMock(side_effect=[RuntimeError("fail"), "success"])
    result = with_retries(mock_fn, attempts=3, backoff_sec=0.01)
    assert result == "success"
    assert mock_fn.call_count == 2


def test_with_retries_exhausted() -> None:
    mock_fn = MagicMock(side_effect=RuntimeError("permanent fail"))
    with pytest.raises(RuntimeError, match="permanent fail"):
        with_retries(mock_fn, attempts=2, backoff_sec=0.01)
