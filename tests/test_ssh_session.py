# -*- coding: utf-8 -*-
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wintermute.ai.utils.ssh_exec import SSHSession


@pytest.mark.asyncio
async def test_connect_success() -> None:
    """SSHSession.connect() opens a connection via asyncssh.connect."""
    mock_conn = AsyncMock()

    with patch(
        "wintermute.ai.utils.ssh_exec.asyncssh.connect", new_callable=AsyncMock
    ) as mock_connect:
        mock_connect.return_value = mock_conn

        session = SSHSession("myhost", username="root", password="pw", port=22)
        await session.connect()

        mock_connect.assert_awaited_once_with(
            host="myhost",
            known_hosts=None,
            username="root",
            password="pw",
            client_keys=None,
            agent_path=None,
            port=22,
        )
        assert session._conn is mock_conn


@pytest.mark.asyncio
async def test_run_returns_json_object() -> None:
    """SSHSession.run() returns {exit_code, stdout, stderr}."""
    mock_result = MagicMock()
    mock_result.exit_status = 0
    mock_result.stdout = "hello\n"
    mock_result.stderr = ""

    mock_conn = AsyncMock()
    mock_conn.run.return_value = mock_result

    session = SSHSession("host")
    session._conn = mock_conn

    result = await session.run("echo hello")

    mock_conn.run.assert_awaited_once_with("echo hello", check=False)
    assert result == {"exit_code": 0, "stdout": "hello\n", "stderr": ""}


@pytest.mark.asyncio
async def test_run_background_returns_job_id() -> None:
    """run_background() returns a job_id and sends a nohup-wrapped command."""
    mock_result = MagicMock()
    mock_result.exit_status = 0
    mock_result.stdout = ""
    mock_result.stderr = ""

    mock_conn = AsyncMock()
    mock_conn.run.return_value = mock_result

    session = SSHSession("host")
    session._conn = mock_conn

    job_id = await session.run_background("sleep 60")

    assert isinstance(job_id, str)
    assert len(job_id) == 12  # hex[:12]

    # Verify the command sent to the connection contains nohup and the job_id
    call_args = mock_conn.run.call_args
    sent_command: str = call_args[0][0]
    assert "nohup" in sent_command
    assert job_id in sent_command
    assert f"/tmp/wm_job_{job_id}.out" in sent_command
    assert f"/tmp/wm_job_{job_id}.err" in sent_command
    assert f"/tmp/wm_job_{job_id}.rc" in sent_command


@pytest.mark.asyncio
async def test_poll_job_running() -> None:
    """poll_job() returns {status: 'running'} when rc file is absent."""
    rc_result = MagicMock()
    rc_result.stdout = ""
    rc_result.stderr = ""

    mock_conn = AsyncMock()
    mock_conn.run.return_value = rc_result

    session = SSHSession("host")
    session._conn = mock_conn

    result = await session.poll_job("abc123")
    assert result == {"status": "running"}


@pytest.mark.asyncio
async def test_poll_job_done() -> None:
    """poll_job() returns full result when rc file exists."""
    rc_result = MagicMock()
    rc_result.stdout = "0\n"

    stdout_result = MagicMock()
    stdout_result.stdout = "output data"

    stderr_result = MagicMock()
    stderr_result.stdout = ""

    mock_conn = AsyncMock()
    mock_conn.run.side_effect = [rc_result, stdout_result, stderr_result]

    session = SSHSession("host")
    session._conn = mock_conn

    result = await session.poll_job("abc123")
    assert result == {
        "status": "done",
        "exit_code": 0,
        "stdout": "output data",
        "stderr": "",
    }


@pytest.mark.asyncio
async def test_close_calls_conn_close() -> None:
    """close() calls conn.close() and wait_closed()."""
    mock_conn = AsyncMock()
    # conn.close() is a regular (non-async) method on SSHClientConnection
    mock_conn.close = MagicMock()

    session = SSHSession("host")
    session._conn = mock_conn

    await session.close()

    mock_conn.close.assert_called_once()
    mock_conn.wait_closed.assert_awaited_once()
    assert session._conn is None


@pytest.mark.asyncio
async def test_is_connected_false_after_close() -> None:
    """is_connected() returns False after close()."""
    mock_conn = AsyncMock()
    mock_conn.close = MagicMock()

    session = SSHSession("host")
    session._conn = mock_conn

    await session.close()
    assert session.is_connected() is False
