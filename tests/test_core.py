import ipaddress
import json

import pytest

from wintermute.core import Analyst, AWSAccount, Device, Operation, User, Vulnerability

"""
Operation test cases
"""


@pytest.fixture
def operation() -> Operation:
    """pytest fixture to create an operation instance for testing."""
    return Operation(
        operation_name="onoSendai",
        ticket="V11223344",
        start_date="01/01/2001",
        end_date="01/01/2001",
    )


def test_operation_creation(operation: Operation) -> None:
    """Test the creation of the Operation instance."""
    assert operation.operation_name == "onoSendai"
    assert operation.ticket == "V11223344"
    assert operation.start_date == "01/01/2001"
    assert operation.end_date == "01/01/2001"


def test_operation_tojson(operation: Operation) -> None:
    """Test the operation of the toJSON() function for Operation"""
    tojson = json.loads(
        '{\n    "analysts": [],\n    "awsaccounts": [],\n    "db": {\n        "_opened": true,\n        "_storage": \
    {\n            "_handle": {\n                "mode": "r+"\n            },\n            "_mode": "r+",\n            "kwargs": \
    {}\n        },\n        "_tables": {}\n    },\n    "devices": [],\n    "end_date": "01/01/2001",\n    \
    "operation_id": "0446d324-2311-11f0-a6a8-54b2030b4724",\n    "operation_name": "onoSendai",\n    \
        "start_date": "01/01/2001",\n    "ticket": "V11223344",\n    "users": []\n}'
    )

    assert tojson["operation_name"] == operation.operation_name
    assert tojson["ticket"] == operation.ticket
    assert tojson["start_date"] == operation.start_date
    assert tojson["end_date"] == operation.end_date
    assert tojson["analysts"] == operation.analysts


"""
User test cases
"""


@pytest.fixture
def user() -> User:
    """pytest fixture to create a user instance for testing."""
    return User(
        uid="500",
        name="nahualito",
        email="nahualito@0hday.org",
        dept="Research & Development",
        permissions=["research", "user", "root"],
    )


def test_user_creation(user: User) -> None:
    """Test the creation of the User instance."""
    assert user.name == "nahualito"
    assert user.uid == "500"
    assert user.email == "nahualito@0hday.org"
    assert user.dept == "Research & Development"
    assert user.permissions == ["research", "user", "root"]


def test_user_tojson(user: User) -> None:
    """Test the operation of the toJSON() function for User"""
    tojson = json.loads(
        '{\n    "AWSAdminAccounts": [],\n    "AWSLoginAccounts": [],\n    "dept": "Research & Development",\n    \
                        "desktops": [],\n    "email": "nahualito@0hday.org",\n    "ldap_groups": [],\n    "name": "nahualito",\n  \
                        "override_reason": "",\n    "permissions": [\n        "research",\n        "user",\n        "root"\n    ],\n \
                        "teams": [],\n    "uid": "500"\n}'
    )

    assert tojson["name"] == user.name
    assert tojson["email"] == user.email
    assert tojson["uid"] == user.uid
    assert tojson["dept"] == user.dept
    assert tojson["permissions"] == user.permissions


"""
Device test cases
"""


@pytest.fixture
def device() -> Device:
    """pytest fixture to create a Device instance for testing."""
    return Device(
        hostname="devicetest",
        macaddr="aa:bb:cc:dd:ee:ff",
        operatingsystem="Linux",
        fqdn="devicetest.0hday.org",
    )


def test_device_creation(device: Device) -> None:
    """Test the creation of the Device instance."""
    assert device.hostname == "devicetest"
    assert device.macaddr == "aa:bb:cc:dd:ee:ff"
    assert device.operatingsystem == "Linux"
    assert device.fqdn == "devicetest.0hday.org"
    assert device.ipaddr == ipaddress.ip_address("127.0.0.1")


def test_device_tojson(device: Device) -> None:
    """Test the operation of the toJSON() function for Device"""
    tojson = json.loads(
        '{\n    "fqdn": "devicetest.0hday.org",\n    "hostname": "devicetest",\n    "ipaddr": "127.0.0.1",\n    \
                        "macaddr": "aa:bb:cc:dd:ee:ff",\n    "operatingsystem": "Linux",\n    "services": []\n}'
    )

    assert tojson["fqdn"] == device.fqdn
    assert tojson["hostname"] == device.hostname
    assert tojson["macaddr"] == device.macaddr
    assert tojson["operatingsystem"] == device.operatingsystem
    assert tojson["ipaddr"] == str(device.ipaddr)


"""
Analyst test cases
"""


@pytest.fixture
def analyst() -> Analyst:
    """pytest fixture to create an Analyst instance for testing."""
    return Analyst(name="Test User", userid="testusr", email="testusr@test.com")


def test_analyst_creation(analyst: Analyst) -> None:
    """Test the creation of the Analyst instance."""
    assert analyst.name == "Test User"
    assert analyst.userid == "testusr"
    assert analyst.email == "testusr@test.com"


def test_analyst_tojson(analyst: Analyst) -> None:
    """Test the toJSON() function for the Analyst instance"""
    tojson = json.loads(
        '{\n    "email": "testusr@test.com",\n    "name": "Test User",\n    "userid": "testusr"\n}'
    )

    assert analyst.name == tojson["name"]
    assert analyst.userid == tojson["userid"]
    assert analyst.email == tojson["email"]


"""
Vulnerability test cases
"""


@pytest.fixture
def vulnerability() -> Vulnerability:
    """pytest fixture to create a Vulnerability instance for testing."""
    return Vulnerability(
        title="Test Vuln",
        description="This is a test vulnerability",
        threat="If it breaks then the package won't work",
        cvss=8,
        mitigation=False,
        fix=True,
        fix_desc="Make sure you have test cases for all",
        mitigation_desc="There are no mitigations",
        verified=True,
    )


def test_vulnerability_creation(vulnerability: Vulnerability) -> None:
    """Test the creation of the Vulnerability object."""
    assert vulnerability.title == "Test Vuln"
    assert vulnerability.description == "This is a test vulnerability"
    assert vulnerability.threat == "If it breaks then the package won't work"
    assert vulnerability.cvss == 8
    assert vulnerability.mitigation is False
    assert vulnerability.fix is True
    assert vulnerability.fix_desc == "Make sure you have test cases for all"
    assert vulnerability.verified is True


def test_vulnerability_tojson(vulnerability: Vulnerability) -> None:
    """Test the toJSON() function for the Vulnerability instance"""
    tojson = json.loads(
        '{\n    "cvss": 8,\n    "description": "This is a test vulnerability",\n    \
                        "fix": true,\n    "fix_desc": "Make sure you have test cases for all",\n    \
                        "mitigation": false,\n    "mitigation_desc": "There are no mitigations",\n   \
                        "reproduction_steps": [],\n    "risk": {\n        "impact": "Low",\n        \
                        "likelihood": "Low",\n        "severity": "Low"\n    },\n    \
                        "threat": "If it breaks then the package won\'t work",\n    \
                        "title": "Test Vuln",\n    "verified": true\n}'
    )

    assert vulnerability.title == tojson["title"]
    assert vulnerability.description == tojson["description"]
    assert vulnerability.cvss == tojson["cvss"]
    assert vulnerability.fix is True
    assert vulnerability.fix_desc == tojson["fix_desc"]
    assert vulnerability.threat == tojson["threat"]


"""
AWSAccount test cases
"""


@pytest.fixture
def awsaccount() -> AWSAccount:
    """pytest fixture to create an AWSAccount instance for testing."""
    return AWSAccount(
        accountId="00112233445566778899",
        name="Test AWS Account",
        description="This is a stub for an AWS account for testing",
    )


def test_awsaccount_creation(awsaccount: AWSAccount) -> None:
    """Test the creation of the AWSAccount objecct."""
    assert awsaccount.accountId == "00112233445566778899"
    assert awsaccount.name == "Test AWS Account"
    assert awsaccount.description == "This is a stub for an AWS account for testing"


def test_awsaccount_tojson(awsaccount: AWSAccount) -> None:
    """Test the toJSON() function for the AWSAccount instance"""
    tojson = json.loads(
        '{\n    "accountId": "00112233445566778899",\n    \
                        "description": "This is a stub for an AWS account for testing",\n    \
                        "name": "Test AWS Account",\n    "vulnerabilities": []\n}'
    )

    assert awsaccount.accountId == tojson["accountId"]
    assert awsaccount.name == tojson["name"]
    assert awsaccount.description == tojson["description"]
