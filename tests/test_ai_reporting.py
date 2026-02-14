from unittest.mock import MagicMock, patch

from wintermute.ai.reporting import get_detailed_test_context, get_findings_context


def test_get_detailed_test_context() -> None:
    mock_op = MagicMock()
    # Mock return: (run, test_case, path)
    mock_run = MagicMock()
    mock_run.run_id = "run-123"
    mock_run.status.name = "not_run"
    mock_run.bound = [MagicMock(kind="UART", object_id="debug-cons")]

    mock_tc = MagicMock()
    mock_tc.code = "TC-01"
    mock_tc.name = "Test UART"
    mock_tc.description = "UART Test"
    mock_tc.execution_mode.name = "automated"
    mock_tc.steps = [
        MagicMock(tool="picocom", action="read", description="Check boot logs")
    ]

    with patch(
        "wintermute.ai.reporting.collect_test_runs",
        return_value=[(mock_run, mock_tc, "/path")],
    ):
        context = get_detailed_test_context(mock_op)

        assert context["scope_summary"]["total_runs_generated"] == 1
        assert "UART" in context["scope_summary"]["interfaces_in_scope"]
        assert context["detailed_runs"][0]["id"] == "run-123"


def test_get_findings_context() -> None:
    mock_op = MagicMock()
    mock_vuln = MagicMock()
    mock_vuln.title = "Buffer Overflow"
    mock_vuln.risk.severity = "High"
    mock_vuln.verified = True
    mock_vuln.description = "Critical bug"

    with patch(
        "wintermute.ai.reporting.collect_vulnerabilities",
        return_value=[(mock_vuln, "/path")],
    ):
        context = get_findings_context(mock_op)
        assert len(context["findings"]) == 1
        assert context["findings"][0]["severity"] == "High"
