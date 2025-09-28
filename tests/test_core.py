# tests/test_core.py
from pathlib import Path
from typing import Any

from wintermute import core
from wintermute.findings import Risk, Vulnerability

# ------------------------
# Helpers
# ------------------------


def make_full_operation(tmp_path: Path) -> core.Operation:
    op = core.Operation("TestOp")

    # Analysts
    assert op.addAnalyst("Alice Analyst", "aalice", "alice@example.com")

    # Devices with nested services/vulns
    assert op.addDevice(
        "host1", "127.0.0.1", "00:11:22:33:44:55", "Linux", "host1.local"
    )
    dev = op.devices[0]
    dev.addService(
        protocol="ipv4",
        app="nginx",
        portNumber=80,
        banner="nginx test",
        transport_layer="HTTP",
    )
    svc = dev.services[0]
    svc.addVulnerability(
        title="Weak TLS",
        description="TLS 1.0 enabled",
        cvss=5,
        risk={"likelihood": "High", "impact": "Medium", "severity": "Moderate"},
    )

    # Users with desktops
    assert op.addUser("jsmith", "John Smith", "john@example.com", ["Red"])
    user = op.users[0]
    user.addDesktop(
        "desktop1", "192.168.1.5", "aa:bb:cc:dd:ee:ff", "Windows", "desk.local"
    )

    # AWS Account with user + vulnerability
    assert op.addAWSAccount("111122223333", "Prod", "Production account")
    aws = op.awsaccounts[0]
    aws.addUser("ajones", "Alice Jones", "alicej@example.com", ["Blue"])
    aws.addVulnerability(
        title="S3 Public Bucket",
        description="World readable bucket",
        cvss=7,
        risk={"likelihood": "High", "impact": "High", "severity": "Critical"},
        verified=True,
    )

    return op


# ------------------------
# Tests
# ------------------------


def test_add_methods_prevent_duplicates() -> None:
    op = core.Operation("DupOp")

    # Analyst
    assert op.addAnalyst("Bob", "bsmith", "bob@example.com")
    assert not op.addAnalyst("Bob", "bsmith", "bob@example.com")

    # Device
    assert op.addDevice("h", "127.0.0.1", "00", "Linux", "h.local")
    assert not op.addDevice("h", "127.0.0.1", "00", "Linux", "h.local")

    # User
    assert op.addUser("u1", "User1", "u1@example.com", ["Team"])
    assert not op.addUser("u1", "User1", "u1@example.com", ["Team"])

    # AWS Account
    assert op.addAWSAccount("acct1", "Account One")
    assert not op.addAWSAccount("acct1", "Account One")


def test_operation_to_dict_and_from_dict() -> None:
    op = make_full_operation(Path("."))

    d = op.to_dict()
    assert "analysts" in d
    assert "devices" in d
    assert "users" in d
    assert "awsaccounts" in d

    op2 = core.Operation.from_dict(d)
    assert isinstance(op2.devices[0], core.Device)
    assert isinstance(op2.devices[0].services[0], core.Service)
    assert isinstance(op2.devices[0].services[0].vulnerabilities[0], Vulnerability)
    assert isinstance(op2.devices[0].services[0].vulnerabilities[0].risk, Risk)


def test_operation_save_and_load(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)

    op = make_full_operation(tmp_path)
    op.save()

    f = tmp_path / "TestOp.json"
    assert f.exists()

    op2 = core.Operation("TestOp")
    op2.load()

    # Analysts survived
    assert len(op2.analysts) == 1
    assert op2.analysts[0].name == "Alice Analyst"

    # Devices -> Service -> Vulnerability -> Risk survived
    dev2 = op2.devices[0]
    svc2 = dev2.services[0]
    vuln2 = svc2.vulnerabilities[0]
    assert vuln2.title == "Weak TLS"
    assert vuln2.risk.likelihood == "High"

    # Users -> Desktop survived
    u2 = op2.users[0]
    assert u2.uid == "jsmith"
    assert u2.desktops[0].hostname == "desktop1"

    # AWS Account -> User + Vulnerability survived
    aws2 = op2.awsaccounts[0]
    assert aws2.users[0].uid == "ajones"
    assert aws2.vulnerabilities[0].risk.severity == "Critical"


def test_pentest_inherits_and_round_trip(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)

    pt = core.Pentest(name="PT1")
    pt.addAnalyst("Pentest Person", "pentester", "pentest@example.com")
    pt.addAWSAccount("444455556666", "TestAccount")
    pt.save()

    f = tmp_path / "PT1.json"
    assert f.exists()

    pt2 = core.Pentest("PT1")
    pt2.load()

    assert pt2.analysts[0].userid == "pentester"
    assert pt2.awsaccounts[0].accountId == "444455556666"
