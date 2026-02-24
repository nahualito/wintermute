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

import importlib
import ipaddress
import types
from typing import Any, Dict, Type

import pytest


# ----- dynamic loader (works with either package or flat file layout) -----
def _import_peripherals_module() -> types.ModuleType:
    candidates = [
        "wintermute.peripherals",  # preferred package import
        "peripherals",  # plain file/module (e.g., tests running next to peripherals.py)
    ]
    last_err: Exception | None = None
    for name in candidates:
        try:
            return importlib.import_module(name)
        except Exception as e:  # pragma: no cover
            last_err = e
    raise ImportError(f"Could not import peripherals module. Last error: {last_err!r}")


def _get_cls(mod: types.ModuleType, name: str) -> Type[Any]:
    cls = getattr(mod, name, None)
    if not isinstance(cls, type):
        raise AttributeError(f"{name} not found in {mod.__name__}")
    return cls


# ----- fixtures -----
@pytest.fixture(scope="module")
def peripherals_mod() -> types.ModuleType:
    return _import_peripherals_module()


@pytest.fixture(scope="module")
def PeripheralType(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "PeripheralType")


@pytest.fixture(scope="module")
def UART(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "UART")


@pytest.fixture(scope="module")
def Wifi(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "Wifi")


@pytest.fixture(scope="module")
def Ethernet(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "Ethernet")


@pytest.fixture(scope="module")
def JTAG(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "JTAG")


@pytest.fixture(scope="module")
def Bluetooth(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "Bluetooth")


# ----- UART -----
def test_uart_defaults_and_types(UART: Type[Any], PeripheralType: Type[Any]) -> None:
    u = UART(device_path="/dev/ttyUSB0")
    assert u.pType == PeripheralType.UART
    assert isinstance(getattr(u, "baudrate"), int)
    assert isinstance(getattr(u, "bytesize"), int)
    assert isinstance(getattr(u, "parity"), str)
    assert isinstance(getattr(u, "stopbits"), int)
    # com_port field is set from comPort arg
    u2 = UART(comPort="/dev/ttyUSB0")
    assert getattr(u2, "com_port") == "/dev/ttyUSB0"


def test_uart_pin_mapping_passthrough(UART: Type[Any]) -> None:
    pins: Dict[str, str] = {"tx": "P1", "rx": "P2", "gnd": "GND"}
    u = UART(device_path="/dev/ttyUSB0", name="dbg", pins=pins)
    assert getattr(u, "name") == "dbg"
    # If your Peripheral stores pins, verify they’re present
    if hasattr(u, "pins"):
        assert getattr(u, "pins")["tx"] == "P1"


# ----- Wifi -----
def test_wifi_defaults_and_variants(Wifi: Type[Any], PeripheralType: Type[Any]) -> None:
    w = Wifi(device_path="wlan0")
    assert w.pType == PeripheralType.Wifi
    assert isinstance(w.SSID, str)
    assert isinstance(w.password, str)
    assert isinstance(w.encryption, str)
    assert isinstance(w.band, str)
    # default in code is "127.0.0.1" (a str)
    assert (
        isinstance(w.ipaddress, (str, ipaddress.IPv4Address, ipaddress.IPv6Address))
        or w.ipaddress is None
    )

    # IPv4/IPv6/None/str variants
    v4 = Wifi(device_path="wlan0", ipaddress=ipaddress.IPv4Address("10.0.0.5"))
    assert isinstance(v4.ipaddress, ipaddress.IPv4Address)
    v6 = Wifi(device_path="wlan0", ipaddress=ipaddress.IPv6Address("::1"))
    assert isinstance(v6.ipaddress, ipaddress.IPv6Address)
    none = Wifi(device_path="wlan0", ipaddress=None)
    assert none.ipaddress is None
    as_str = Wifi(device_path="wlan0", ipaddress="192.168.1.77")
    assert isinstance(as_str.ipaddress, str)


# ----- Ethernet -----
def test_ethernet_basic_fields(Ethernet: Type[Any], PeripheralType: Type[Any]) -> None:
    e = Ethernet(
        device_path="eth0",
        name="eth0",
        mac_address="00:11:22:33:44:55",
        ipaddress=ipaddress.IPv4Address("192.168.0.10"),
        subnet_mask=ipaddress.ip_network("192.168.0.0/24"),
        gateway="192.168.0.1",
        dns="8.8.8.8",
        speed="1Gbps",
        duplex="full",
    )
    assert e.pType == PeripheralType.Ethernet
    assert e.mac_address == "00:11:22:33:44:55"
    assert isinstance(e.ipaddress, ipaddress.IPv4Address)
    assert getattr(e, "speed") == "1Gbps"
    assert getattr(e, "duplex") == "full"


def test_ethernet_union_params(Ethernet: Type[Any]) -> None:
    e1 = Ethernet(
        device_path="eth0",
        ipaddress="10.0.0.9",
        subnet_mask="255.255.255.0",
        gateway=None,
        dns=None,
    )
    assert isinstance(e1.ipaddress, str)
    assert isinstance(e1.subnet_mask, str)

    e2 = Ethernet(
        device_path="eth0",
        ipaddress=None,
        subnet_mask=None,
        gateway=ipaddress.IPv6Address("::1"),
    )
    assert e2.ipaddress is None
    assert isinstance(e2.gateway, ipaddress.IPv6Address)


# ----- JTAG -----
def test_jtag_minimal(JTAG: Type[Any], PeripheralType: Type[Any]) -> None:
    # Current code sets pType and name; per-pin convenience fields were removed in this version.
    j = JTAG(device_path="jtag0", name="jtag1", pins={"tck": "P1"})
    assert j.pType == PeripheralType.JTAG
    assert getattr(j, "name") == "jtag1"


# ----- Bluetooth -----
def test_bluetooth_defaults(Bluetooth: Type[Any], PeripheralType: Type[Any]) -> None:
    b = Bluetooth(device_path="hci0")
    assert b.pType == PeripheralType.Bluetooth
    assert isinstance(b.device_name, str)
    assert isinstance(b.mac_address, str)
    assert isinstance(b.paired_devices, list)
