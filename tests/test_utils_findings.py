# -*- coding: utf-8 -*-
from typing import List

from wintermute.findings import Vulnerability
from wintermute.utils.findings import (
    add_reproduction_step,
    add_vulnerability,
    get_vulnerability,
    remove_vulnerability,
)


class MockDevice:
    def __init__(self) -> None:
        self.vulnerabilities: List[Vulnerability] = []


def test_add_vulnerability() -> None:
    device = MockDevice()
    vuln = add_vulnerability(
        device,
        title="Test Vuln",
        description="A test vulnerability",
        threat="High",
        cvss=7,
        risk={"likelihood": "High", "impact": "Medium", "severity": "High"},
    )

    assert len(device.vulnerabilities) == 1
    assert device.vulnerabilities[0].title == "Test Vuln"
    assert device.vulnerabilities[0].risk.severity == "High"
    assert vuln == device.vulnerabilities[0]


def test_get_vulnerability() -> None:
    device = MockDevice()
    vuln1 = add_vulnerability(device, title="Vuln 1", description="Desc 1")
    vuln2 = add_vulnerability(device, title="Vuln 2", description="Desc 2")

    # Test get by title
    assert get_vulnerability(device, title="Vuln 1") == vuln1
    assert get_vulnerability(device, title="Vuln 2") == vuln2
    assert get_vulnerability(device, title="Nonexistent") is None

    # Test get by uid (assuming it has one)
    uid = getattr(vuln1, "uid", None)
    if uid:
        assert get_vulnerability(device, uid=uid) == vuln1


def test_add_reproduction_step() -> None:
    device = MockDevice()
    vuln = add_vulnerability(device, title="Vuln 1", description="Desc 1")

    step_data = {
        "title": "Repro Step",
        "description": "Step desc",
        "tool": "nmap",
        "action": "scan",
    }

    success = add_reproduction_step(device, title="Vuln 1", step=step_data)
    assert success is True
    assert len(vuln.reproduction_steps) == 1
    assert vuln.reproduction_steps[0].title == "Repro Step"

    # Test with invalid vulnerability title
    success_fail = add_reproduction_step(device, title="Nonexistent", step=step_data)
    assert success_fail is False


def test_remove_vulnerability() -> None:
    device = MockDevice()
    _vuln1 = add_vulnerability(device, title="Vuln 1", description="Desc 1")
    _vuln2 = add_vulnerability(device, title="Vuln 2", description="Desc 2")

    assert len(device.vulnerabilities) == 2

    # Remove by title
    success = remove_vulnerability(device, title="Vuln 1")
    assert success is True
    assert len(device.vulnerabilities) == 1
    assert device.vulnerabilities[0].title == "Vuln 2"

    # Remove nonexistent
    success_fail = remove_vulnerability(device, title="Nonexistent")
    assert success_fail is False
    assert len(device.vulnerabilities) == 1
