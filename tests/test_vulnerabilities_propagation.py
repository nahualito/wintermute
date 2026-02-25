# -*- coding: utf-8 -*-
from wintermute.core import Device, User
from wintermute.findings import Vulnerability
from wintermute.peripherals import JTAG, TPM, UART, USB, Bluetooth, Ethernet, PCIe, Wifi


def test_device_vulnerabilities_init() -> None:
    """Test initializing Device with vulnerabilities."""
    vuln_dict = {
        "title": "Device Vuln",
        "description": "A vulnerability on the device itself",
        "cvss": 9,
    }
    vuln_obj = Vulnerability(title="Device Vuln Obj", cvss=8)

    device = Device(hostname="test-host", vulnerabilities=[vuln_dict, vuln_obj])

    assert len(device.vulnerabilities) == 2
    assert device.vulnerabilities[0].title == "Device Vuln"
    assert device.vulnerabilities[1].title == "Device Vuln Obj"
    assert isinstance(device.vulnerabilities[0], Vulnerability)


def test_user_vulnerabilities_init() -> None:
    """Test initializing User with vulnerabilities."""
    vuln_dict = {
        "title": "Weak Password",
        "description": "User has weak password",
        "cvss": 5,
    }

    user = User(
        uid="testuser",
        name="Test User",
        email="test@example.com",
        teams=["Red"],
        vulnerabilities=[vuln_dict],
    )

    assert len(user.vulnerabilities) == 1
    assert user.vulnerabilities[0].title == "Weak Password"
    assert isinstance(user.vulnerabilities[0], Vulnerability)


def test_peripheral_vulnerabilities_init() -> None:
    """Test initializing various Peripherals with vulnerabilities."""
    vuln = {"title": "Hardware Vuln", "cvss": 7}

    # UART
    uart = UART(name="uart0", vulnerabilities=[vuln])
    assert len(uart.vulnerabilities) == 1
    assert uart.vulnerabilities[0].title == "Hardware Vuln"

    # Wifi
    wifi = Wifi(name="wlan0", vulnerabilities=[vuln])
    assert len(wifi.vulnerabilities) == 1

    # Ethernet
    eth = Ethernet(name="eth0", vulnerabilities=[vuln])
    assert len(eth.vulnerabilities) == 1

    # JTAG
    jtag = JTAG(name="jtag0", vulnerabilities=[vuln])
    assert len(jtag.vulnerabilities) == 1

    # Bluetooth
    bt = Bluetooth(name="hci0", vulnerabilities=[vuln])
    assert len(bt.vulnerabilities) == 1

    # USB
    usb = USB(name="usb0", vulnerabilities=[vuln])
    assert len(usb.vulnerabilities) == 1

    # PCIe
    pcie = PCIe(name="pcie0", vulnerabilities=[vuln])
    assert len(pcie.vulnerabilities) == 1

    # TPM
    tpm = TPM(name="tpm0", vulnerabilities=[vuln])
    assert len(tpm.vulnerabilities) == 1


def test_device_serialization_with_vulnerabilities() -> None:
    """Test that vulnerabilities in Device are correctly serialized and deserialized."""
    vuln = {"title": "Serialized Vuln", "cvss": 6.5}
    device = Device(hostname="serialization-test", vulnerabilities=[vuln])

    data = device.to_dict()
    assert "vulnerabilities" in data
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["title"] == "Serialized Vuln"

    # Deserialize
    device2 = Device.from_dict(data)
    assert len(device2.vulnerabilities) == 1
    assert device2.vulnerabilities[0].title == "Serialized Vuln"
    assert isinstance(device2.vulnerabilities[0], Vulnerability)


def test_user_serialization_with_vulnerabilities() -> None:
    """Test that vulnerabilities in User are correctly serialized and deserialized."""
    vuln = {"title": "User Serialized Vuln", "cvss": 4.0}
    user = User(uid="user_serial", vulnerabilities=[vuln])

    data = user.to_dict()
    assert "vulnerabilities" in data

    user2 = User.from_dict(data)
    assert len(user2.vulnerabilities) == 1
    assert user2.vulnerabilities[0].title == "User Serialized Vuln"


def test_peripheral_serialization_with_vulnerabilities() -> None:
    """Test that vulnerabilities in Peripheral are correctly serialized and deserialized."""
    vuln = {"title": "Peri Serialized Vuln", "cvss": 8.0}
    uart = UART(name="uart_serial", vulnerabilities=[vuln])

    data = uart.to_dict()
    assert "vulnerabilities" in data

    uart2 = UART.from_dict(data)
    assert len(uart2.vulnerabilities) == 1
    assert uart2.vulnerabilities[0].title == "Peri Serialized Vuln"
