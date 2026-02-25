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

"""
Peripherals classes for Wintermute
----------------------------------

This file contains the peripheral metaclass and the classes that inherit from it
to give access to hardware peripherals and have more abstraction for automation
and attacking.
"""

import ipaddress
import logging
import struct
from enum import Enum
from typing import Any, Dict, List, Optional

from .basemodels import Peripheral, PeripheralType
from .findings import Vulnerability
from .hardware import Architecture, Memory, Processor

log = logging.getLogger(__name__)


class UART(Peripheral):
    """Class that defines the UART interface

    Examples:
        >>> pins = {"tx": "P1", "rx": "P2", "gnd": "GND"}
        >>> u = UART(name="dbg", pins=pins, comPort="/dev/ttyUSB0")
        >>> print(u)
        name='dbg' pins={'tx': 'P1', 'rx': 'P2', 'gnd': 'GND'} pType=<PeripheralType.UART: 1>
        >>> print(u.tx, u.rx, u.gnd)
        P1 P2 GND
        >>> print(u.baudrate, u.bytesize, u.parity, u.stopbits)
        9600 8 N 1

    Attributes:
        name (str): Name of the peripheral
        pins (Dict[Any, Any]): Dictionary of pin names to their values
        pType (PeripheralType): Type of the peripheral
        tx (str): Pin name for TX
        rx (str): Pin name for RX
        gnd (str): Pin name for GND
        baudrate (int): Baud rate for UART communication
        bytesize (int): Number of data bits
        parity (str): Parity bit setting ('N', 'E', 'O')
        stopbits (int): Number of stop bits
        com_port (str): Port connected to the user's device to speak to the UART

    """

    def __init__(
        self,
        device_path: str = "",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.UART,
        baudrate: int = 9600,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: int = 1,
        comPort: str = "",
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.pType = pType
        self.com_port = (
            device_path or comPort
        )  # Port connected to the user's device to speak to the UART

        super().__init__(
            device_path=self.com_port,
            name=name,
            pins=pins,
            pType=pType,
            vulnerabilities=vulnerabilities,
        )
        log.info(
            f"Initialized UART peripheral {name} on port {self.com_port} with baudrate {baudrate}"
        )


class Wifi(Peripheral):
    """Class that defines the Wifi interface"""

    def __init__(
        self,
        device_path: str = "wlan0",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.Wifi,
        SSID: str = "",
        password: str = "",
        encryption: str = "WPA2",
        band: str = "2.4GHz",
        ipaddress: str
        | ipaddress.IPv4Address
        | ipaddress.IPv6Address
        | None = "127.0.0.1",
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.pType = pType
        self.SSID = SSID
        self.password = password
        self.encryption = encryption
        self.band = band
        self.ipaddress = ipaddress

        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(f"Initialized Wifi peripheral {name} with SSID {SSID} on band {band}")


class Ethernet(Peripheral):
    """Class that defines the Ethernet interface.

    This class can be used to define the Ethernet peripheral of a device, including
    its MAC address, IP address, subnet mask, gateway, DNS server, speed, and duplex mode.
    Pins can also be defined for the peripheral. The usual pins found on ethernet connectors are:
    RXD0, RXD1, RXD2, RXD3, TXD0, TXD1, TXD2, TXD3, RX_DV, LED1, RX_CLK, TX_CLK, TXEN, MDIO, MDC.

    Examples:
        >>> pins = {
        ...     "RXD0": "P1",
        ...     "RXD1": "P2",
        ...     "RXD2": "P3",
        ...     "RXD3": "P4",
        ...     "TXD0": "P5",
        ...     "TXD1": "P6",
        ...     "TXD2": "P7",
        ...     "TXD3": "P8",
        ...     "RX_DV": "P9",
        ...     "LED1": "P10",
        ...     "RX_CLK": "P11",
        ...     "TX_CLK": "P12",
        ...     "TXEN": "P13",
        ...     "MDIO": "P14",
        ...     "MDC": "P15",
        ...     "GND": "GND",
        ...     "VCC": "VCC",
        ... }
        >>> eth = ethernet(
        ...     name="eth0",
        ...     pins=pins,
        ...     mac_address="00:11:22:33:44:55",
        ...     ipaddress=""
        ...     subnet_mask=""
        ...     gateway=""
        ...     dns=""
        ...     speed="1Gbps"
        ...     duplex="full"
        ... )
        >>> print(eth)
        name='eth0' pins={'RXD0': 'P1', 'RXD1': 'P2', 'RXD2': 'P3', 'RXD3': 'P4', 'TXD0': 'P5', 'TXD1': 'P6',
        'TXD2': 'P7', 'TXD3': 'P8', 'RX_DV': 'P9', 'LED1': 'P10', 'RX_CLK': 'P11', 'TX_CLK': 'P12', 'TXEN': 'P13',
        'MDIO': 'P14', 'MDC': 'P15', 'GND': 'GND', 'VCC': 'VCC'} pType=<PeripheralType.Ethernet: 2>

    Attributes:
        name (str): Name of the peripheral
        pins (Dict[Any, Any]): Dictionary of pin names to their values
        pType (PeripheralType): Type of the peripheral
        mac_address (str): MAC address of the Ethernet interface
        ipaddress (ipaddress.IPv4Address | ipaddress.IPv6Address | None): IP address of the Ethernet interface
        subnet_mask (ipaddress.IPv4Address | ipaddress.IPv6Address | None): Subnet mask of the Ethernet interface
        gateway (ipaddress.IPv4Address | ipaddress.IPv6Address | None): Gateway of the Ethernet interface
        dns (ipaddress.IPv4Address | ipaddress.IPv6Address | None): DNS server of the Ethernet interface
        speed (str): Speed of the Ethernet interface (e.g., "10Mbps", "100Mbps", "1Gbps")
        duplex (str): Duplex mode of the Ethernet interface ("half" or "full")
    """

    def __init__(
        self,
        device_path: str = "eth0",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.Ethernet,
        mac_address: str = "",
        ipaddress: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
        subnet_mask: str | ipaddress.IPv4Network | ipaddress.IPv6Network | None = None,
        gateway: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
        dns: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
        speed: str = "1Gbps",
        duplex: str = "full",
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.pType = pType
        self.mac_address = mac_address
        self.ipaddress = ipaddress
        self.subnet_mask = subnet_mask
        self.gateway = gateway
        self.dns = dns
        self.speed = speed
        self.duplex = duplex

        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(
            f"Initialized Ethernet peripheral {name} with MAC {mac_address} at IP {ipaddress}"
        )


class JTAG(Peripheral):
    """Class that defines the JTAG interface

    Examples:
        >>> pins = {
        ...     "tck": "P1",
        ...     "tdi": "P2",
        ...     "tdo": "P3",
        ...     "tms": "P4",
        ...     "trst": "P5",
        ...     "gnd": "GND",
        ...     "vcc": "VCC",
        ... }
        >>> j = JTAG(name="jtag1", pins=pins)
        >>> print(j)
        name='jtag1' pins={'tck': 'P1', 'tdi': 'P2', 'tdo': 'P3', 'tms': 'P4', 'trst': 'P5', 'gnd': 'GND', 'vcc': 'VCC'} pType=<PeripheralType.JTAG: 3>
        >>> print(j.tck, j.tdi, j.tdo, j.tms, j.trst, j.gnd, j.vcc)
        P1 P2 P3 P4 P5 GND VCC
    Attributes:
        name (str): Name of the peripheral
        pins (Dict[Any, Any]): Dictionary of pin names to their values
        pType (PeripheralType): Type of the peripheral
    """

    def __init__(
        self,
        device_path: str = "",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.JTAG,
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.pType = pType
        self.name = name
        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(f"Initialized JTAG peripheral {name}")


class Bluetooth(Peripheral):
    """Class that defines the Bluetooth interface"""

    def __init__(
        self,
        device_path: str = "hci0",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.Bluetooth,
        device_name: str = "",
        mac_address: str = "",
        paired_devices: list[str] = [],
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.pType = pType
        self.device_name = device_name
        self.mac_address = mac_address
        self.paired_devices = paired_devices

        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(
            f"Initialized Bluetooth peripheral {name} with device name {device_name} and MAC {mac_address}"
        )


class USB(Peripheral):
    """Class that defines the USB interface"""

    def __init__(
        self,
        device_path: str = "",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.USB,
        version: str = "2.0",
        speed: str = "480Mbps",
        role: str = "host",
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.pType = pType
        self.version = version
        self.speed = speed
        self.role = role

        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(
            f"Initialized USB peripheral {name} with version {version}, speed {speed}, role {role}"
        )


class PCIe(Peripheral):
    """Class that defines the PCIe interface"""

    __schema__ = {
        "Processor": Processor,
        "Architecture": Architecture,
        "Memory": Memory,
    }
    __enums__ = {}

    def __init__(
        self,
        device_path: str = "",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.PCIe,
        version: str = "4.0",
        lanes: int = 1,
        role: str = "endpoint",  # GPU, Co-Processor, Network Card, etc.
        processor: Processor
        | None = None,  # CPU or SoC connected via PCIe or in the PCIe device
        architecture: Architecture | None = None,
        memory: Memory | None = None,
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.pType = pType
        self.version = version
        self.lanes = lanes
        self.role = role
        self.processor = processor
        self.architecture = architecture
        self.memory = memory

        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(
            f"Initialized PCIe peripheral {name} with version {version}, lanes {lanes}, role {role}"
        )


class TPM_register(Enum):
    TPM_ACCESS = 0x0000
    TPM_STS = 0x0001
    TPM_BURST_CNT = 0x0002
    TPM_DATA_FIFO = 0x0005
    TPM_DID_VID = 0x0006
    TPM_REG_NONE = 0xFFFF


class TPM_interposer_commands(Enum):
    """TPM Command ordinals that the interposer is aware"""

    TPM_ORD_OIAP = 0x0A
    TPM_ORD_OSAP = 0x0B
    TPM_ORD_TakeOwnership = 0x0D
    TPM_ORD_Extend = 0x14
    TPM_ORD_PcrRead = 0x15
    TPM_ORD_GetRandom = 0x46
    TPM_ORD_SelfTest = 0x50
    TPM_ORD_ContinueSelfTest = 0x53
    TPM_ORD_OwnerClear = 0x5B
    TPM_ORD_GetCapability = 0x65
    TPM_ORD_GetCapabilityOwner = 0x66
    TPM_ORD_OwnerSetDisable = 0x6E
    TPM_ORD_PhysicalEnable = 0x6F
    TPM_ORD_SetOwnerInstall = 0x71
    TPM_ORD_PhysicalSetDeactivated = 0x72
    TPM_ORD_SetOperatorAuth = 0x74
    TPM_ORD_ReadPubek = 0x7C
    TPM_ORD_OwnerReadInternalPub = 0x81
    TPM_ORD_Startup = 0x99
    TPM_ORD_FlushSpecific = 0xBA
    TPM_ORD_NV_ReadValue = 0xCF
    TSC_ORD_PhysicalPresence = 0x4000000A


class TPM(Peripheral):
    """Class that defines a TPM peripheral

    Examples:
        >>> pins = {
        ...     "mosi": "P1",
        ...     "miso": "P2",
        ...     "sclk": "P3",
        ...     "gnd": "GND",
        ...     "cs": "P4",
        ...     "rst": "P5",
        ...     "pirq": "P6",
        ...     "vcc": "VCC",
        ... }
        >>> tpm = TPM(name="tpm1", pins=pins)
        >>> print(tpm)
        name='tpm1' pins={'mosi': 'P1', 'miso': 'P2', 'sclk': 'P3', 'gnd': 'GND', 'cs': 'P4', 'rst': 'P5', 'pirq': 'P6', 'vcc': 'VCC'} pType=<PeripheralType.TPM: 10>
        >>> print(
        ...     tpm.mosi,
        ...     tpm.miso,
        ...     tpm.sclk,
        ...     tpm.gnd,
        ...     tpm.cs,
        ...     tpm.rst,
        ...     tpm.pirq,
        ...     tpm.vcc,
        ... )
        P1 P2 P3 GND P4 P5 P6 VCC

    Attributes:
        name (str): Name of the peripheral
        pins (Dict[Any, Any]): Dictionary of pin names to their values
        pType (PeripheralType): Type of the peripheral
    """

    def __init__(
        self,
        device_path: str = "/dev/tpm0",
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.TPM,
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        """Initialize TPM peripheral with pin mappings and type.

        Args:
            device_path (str): Path to the TPM device file.
            name (str): Name of the TPM peripheral.
            pins (Dict[Any, Any]): Dictionary mapping pin names to their values.
            pType (PeripheralType): Type of the peripheral, defaults to PeripheralType.TPM.
        """
        super().__init__(
            device_path, name, pins, pType, vulnerabilities=vulnerabilities
        )
        log.info(f"Initialized TPM peripheral {name} at {device_path}")

    def _tpm_input_header(self, tag: int, len: int, code: int) -> bytes:
        """10 byte header that will prepend every command sent from the host to the TPM"""
        return struct.pack(">HII", tag, len, code)

    def _tpm_output_header(self, tag: int, len: int, code: int) -> bytes:
        """10 byte header that will prepend every command sent from the TPM to the host"""
        return struct.pack(">HII", tag, len, code)

    # -------------------------------------------------
    # PCR Read
    # -------------------------------------------------

    def _tpm_pcr_read_req_body(self, pcr_index: int = 0) -> bytes:
        return struct.pack(">I", pcr_index)

    def _tpm_pcr_read_resp_body(self, out_digest: bytes) -> bytes:
        return struct.pack(">20s", out_digest)

    # -------------------------------------------------
    # PCR Extend
    # -------------------------------------------------

    def _tpm_pcr_extend_req_body(self, pcr_index: int, in_digest: bytes) -> bytes:
        """PCR Extend"""
        return struct.pack(">I20s", pcr_index, in_digest)

    def _tpm_pcr_extend_resp_body(self, out_digest: bytes) -> bytes:
        return struct.pack(">20s", out_digest)

    # -------------------------------------------------
    # Get Random
    # -------------------------------------------------

    def _tpm_get_rnd_req_body(self, num_bytes: int) -> bytes:
        return struct.pack(">I", num_bytes)

    def _tpm_get_rnd_resp_body(
        self, random_bytes_size: int, random_bytes: bytes
    ) -> bytes:
        return struct.pack(">I128s", random_bytes_size, random_bytes)

    # -------------------------------------------------
    # Set Operator Auth
    # -------------------------------------------------

    def _tpm_op_auth_req_body(self, operator_auth: bytes) -> bytes:
        return struct.pack(">20s", operator_auth)
