import pytest
import json
import ipaddress

from wintermute.core import Operation, User, Device

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
    tojson = json.loads('{\n    "analysts": [],\n    "awsaccounts": [],\n    "db": {\n        "_opened": true,\n        "_storage": \
    {\n            "_handle": {\n                "mode": "r+"\n            },\n            "_mode": "r+",\n            "kwargs": \
    {}\n        },\n        "_tables": {}\n    },\n    "devices": [],\n    "end_date": "01/01/2001",\n    \
    "operation_id": "0446d324-2311-11f0-a6a8-54b2030b4724",\n    "operation_name": "onoSendai",\n    \
        "start_date": "01/01/2001",\n    "ticket": "V11223344",\n    "users": []\n}')
    
    assert tojson['operation_name'] == operation.operation_name
    assert tojson['ticket'] == operation.ticket
    assert tojson['start_date'] == operation.start_date
    assert tojson['end_date'] == operation.end_date
    assert tojson['analysts'] == operation.analysts

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
        permissions=['research', 'user', 'root']
    )

def test_user_creation(user: User) -> None:
    """Test the creation of the User instance."""
    assert user.name == "nahualito"
    assert user.uid == "500"
    assert user.email == "nahualito@0hday.org"
    assert user.dept =="Research & Development"
    assert user.permissions == ['research', 'user', 'root']

def test_user_tojson(user: User) -> None:
    """Test the operation of the toJSON() function for User"""
    tojson = json.loads('{\n    "AWSAdminAccounts": [],\n    "AWSLoginAccounts": [],\n    "dept": "Research & Development",\n    \
                        "desktops": [],\n    "email": "nahualito@0hday.org",\n    "ldap_groups": [],\n    "name": "nahualito",\n  \
                        "override_reason": "",\n    "permissions": [\n        "research",\n        "user",\n        "root"\n    ],\n \
                        "teams": [],\n    "uid": "500"\n}')
    
    assert tojson['name'] == user.name
    assert tojson['email'] == user.email
    assert tojson['uid'] == user.uid
    assert tojson['dept'] == user.dept
    assert tojson['permissions'] == user.permissions

"""
Device test cases
"""

@pytest.fixture
def device() -> Device:
    """pytest fixture to create a Device isntance for testing."""
    return Device(
        hostname='devicetest',
        macaddr="aa:bb:cc:dd:ee:ff",
        operatingsystem="Linux",
        fqdn="devicetest.0hday.org",
    )

def test_device_creation(device: Device) -> None:
    """Test the creation of the Device instance."""
    assert device.hostname == 'devicetest'
    assert device.macaddr == "aa:bb:cc:dd:ee:ff"
    assert device.operatingsystem == "Linux"
    assert device.fqdn == "devicetest.0hday.org"
    assert device.ipaddr == ipaddress.ip_address("127.0.0.1")

def test_device_tojson(device: Device) -> None:
    """Test the operation of the toJSON() function for Device"""
    tojson = json.loads('{\n    "fqdn": "devicetest.0hday.org",\n    "hostname": "devicetest",\n    "ipaddr": "127.0.0.1",\n    \
                        "macaddr": "aa:bb:cc:dd:ee:ff",\n    "operatingsystem": "Linux",\n    "services": []\n}')
    
    assert tojson['fqdn'] == device.fqdn
    assert tojson['hostname'] == device.hostname
    assert tojson['macaddr'] == device.macaddr
    assert tojson['operatingsystem'] == device.operatingsystem
    assert tojson['ipaddr'] == str(device.ipaddr)