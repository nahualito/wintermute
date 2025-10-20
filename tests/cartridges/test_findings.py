# tests/test_findings.py
from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from wintermute.findings import ReproductionStep, Risk, Vulnerability


def test_reproduction_step_to_from_dict_round_trip() -> None:
    rs = ReproductionStep(
        title="Scan",
        description="Run nmap",
        tool="nmap",
        action="scan",
        confidence=7,
        arguments=["-sV", "--script=vuln"],
        vulnOutput="found stuff",
        fixOutput="applied patch",
    )
    d = rs.to_dict()
    assert d["title"] == "Scan"
    assert d["confidence"] == 7
    assert d["arguments"] == ["-sV", "--script=vuln"]

    rs2 = ReproductionStep.from_dict(json.loads(json.dumps(d)))
    assert rs2.title == "Scan"
    assert rs2.tool == "nmap"
    assert rs2.arguments == ["-sV", "--script=vuln"]


def test_risk_defaults_and_custom_values() -> None:
    r_default = Risk()
    assert r_default.severity == "Low"
    assert r_default.likelihood == "Low"
    assert r_default.impact == "Low"

    r = Risk(likelihood="High", impact="Medium", severity="Critical")
    d = r.to_dict()
    assert d["severity"] == "Critical"
    r2 = Risk.from_dict(d)
    assert r2.severity == "Critical"
    assert r2.likelihood == "High"
    assert r2.impact == "Medium"


def test_vulnerability_init_with_risk_dict_and_steps_instances() -> None:
    steps: List[ReproductionStep] = [
        ReproductionStep(title="repro1", tool="curl"),
        ReproductionStep(title="repro2", tool="nmap"),
    ]
    v = Vulnerability(
        title="CVE-XYZ",
        description="desc",
        threat="RCE",
        cvss=9,
        mitigation=False,
        fix=True,
        fix_desc="patch X",
        mitigation_desc="WAF",
        risk={"likelihood": "High", "impact": "High", "severity": "Critical"},
        verified=True,
        reproduction_steps=steps,
    )
    assert v.title == "CVE-XYZ"
    assert v.cvss == 9
    assert v.verified is True
    assert v.risk.severity == "Critical"
    assert len(v.reproduction_steps) == 2
    assert v.reproduction_steps[0].title == "repro1"


def test_vulnerability_from_dict_coerces_schema_nested_types() -> None:
    payload: Dict[str, Any] = {
        "title": "CVE-2025-0001",
        "description": "Example",
        "threat": "RCE",
        "cvss": 8,
        "mitigation": True,
        "fix": False,
        "fix_desc": "none",
        "mitigation_desc": "segmentation",
        "verified": False,
        "risk": {"likelihood": "Low", "impact": "High", "severity": "Medium"},
        "reproduction_steps": [
            {"title": "run curl", "tool": "curl"},
            {"title": "nmap", "tool": "nmap"},
        ],
    }
    v = Vulnerability.from_dict(payload)
    assert v.title == "CVE-2025-0001"
    assert v.risk.impact == "High"  # dict → Risk
    assert len(v.reproduction_steps) == 2  # dicts → ReproductionStep
    assert isinstance(v.reproduction_steps[0], ReproductionStep)


def test_vulnerability_setRisk_overwrites_risk() -> None:
    v = Vulnerability(
        title="CVE", risk={"likelihood": "Low", "impact": "Low", "severity": "Low"}
    )
    v.setRisk(likelihood="High", impact="High", severity="Critical")
    assert v.risk.severity == "Critical"
    assert v.risk.likelihood == "High"
    assert v.risk.impact == "High"


def test_vulnerability_from_dict_raises_on_bad_reproduction_item_type() -> None:
    bad: Dict[str, Any] = {
        "title": "Bad",
        "reproduction_steps": [42],  # invalid item for a schema'd list
    }
    with pytest.raises(TypeError):
        Vulnerability.from_dict(bad)
