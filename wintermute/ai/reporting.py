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

from __future__ import annotations

import json
from typing import Any, Dict, cast

from wintermute.ai.json_types import JSONObject
from wintermute.ai.provider import Router
from wintermute.ai.tools_runtime import Tool, tools
from wintermute.ai.use import simple_chat
from wintermute.reports import collect_test_runs, collect_vulnerabilities

# --- Context Helpers ---


def get_detailed_test_context(op: object) -> Dict[str, Any]:
    """
    Extracts comprehensive planning data including descriptions and steps.
    """
    runs_data = []

    # We aggregate by interface to help the AI structure the report
    interfaces_targeted = set()

    for run, tc, _path in collect_test_runs([op]):
        # Extract target info (e.g., "UART:debug-console")
        targets = [f"{b.kind}:{b.object_id}" for b in run.bound]

        # Track unique interfaces for the summary high-level view
        for t in targets:
            if ":" in t:
                interfaces_targeted.add(t.split(":")[0])  # e.g. "UART", "JTAG"

        # Serialize steps if available
        steps_summary = []
        if tc and tc.steps:
            for step in tc.steps:
                # Format: "Tool (Action): Description"
                s_str = f"{step.tool or 'Manual'} ({step.action or 'Check'}): {step.description or step.title}"
                steps_summary.append(s_str)

        runs_data.append(
            {
                "id": run.run_id,
                "test_case": tc.code if tc else "Unknown",
                "name": tc.name if tc else "Unknown",
                "description": tc.description if tc else "",
                "status": run.status.name,
                "targets": targets,
                "execution_mode": tc.execution_mode.name if tc else "unknown",
                "steps": steps_summary,  # <--- The AI needs this to understand the strategy
            }
        )

    return {
        "timestamp": "Current",
        "scope_summary": {
            "total_runs_generated": len(runs_data),
            "interfaces_in_scope": list(interfaces_targeted),
            "pending_execution": len(
                [r for r in runs_data if r["status"] == "not_run"]
            ),
        },
        "detailed_runs": runs_data,
    }


def get_findings_context(op: object) -> Dict[str, Any]:
    """Extracts ONLY vulnerability data."""
    vulns = []
    for v, _path in collect_vulnerabilities([op]):
        vulns.append(
            {
                "title": v.title,
                "severity": getattr(v.risk, "severity", "Unknown"),
                "status": "Verified" if v.verified else "Potential",
                "description": v.description,
            }
        )
    return {"phase": "Reporting", "findings": vulns}


# --- Tool Registration ---


def _register_findings_tool(op: object) -> str:
    name = "fetch_security_findings"
    input_schema: JSONObject = {"type": "object", "properties": {}}
    output_schema: JSONObject = {
        "type": "object",
        "properties": {"findings": {"type": "array", "items": {"type": "object"}}},
    }

    def _handler(_: JSONObject) -> JSONObject:
        return cast(JSONObject, get_findings_context(op))

    tools.register(
        Tool(
            name=name,
            input_schema=input_schema,
            output_schema=output_schema,
            handler=_handler,
        )
    )
    return name


# --- Generator Function ---


def generate_execution_strategy_report(router: Router, op: object) -> str:
    """
    Generates the Test Execution Strategy report by pre-injecting the plan data.
    """
    # 1. PRE-FETCH DATA (Context Injection)
    # We get the data directly using Python, no AI tool guessing required.
    context_data = get_detailed_test_context(op)

    # Convert to JSON string for the prompt
    context_json = json.dumps(context_data, indent=2)

    # 2. CONSTRUCT PROMPT WITH DATA
    system_instruction = (
        "You are a seasoned Hardware Security Engineer Lead creating a Test Plan Summary. "
        "The testing phase has NOT finished (or hasn't started). "
        "Use the provided JSON context to write the report. "
        "Do NOT hallucinate test cases. Use ONLY the 'detailed_runs' provided.\n"
        "Focus on:\n"
        "1. Scope: Which interfaces (UART, JTAG, etc.) are targeted?\n"
        "2. Strategy: What methodology is used? (Analyze the 'steps' in the JSON)\n"
        "3. Coverage: How many tests per interface?"
    )

    user_prompt = (
        f"Summarize the planned test execution strategy based on the following Test Run Data:\n\n"
        f"```json\n{context_json}\n```"
    )

    # 3. CALL AI
    # We use simple_chat because we already have the tool output
    full_prompt = f"{system_instruction}\n\n{user_prompt}"

    return simple_chat(router, full_prompt)
