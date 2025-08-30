# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long

"""
Peripherals classes for onoSendai
----------------------------------

This file contains the peripheral metaclass and the classes that inherit from it
to give access to hardware peripherals and have more abstraction for automation
and attacking.
"""

import struct
from enum import Enum
from typing import Any, Dict

from .core import BaseModel


class PeripheralType(Enum):
    Unknown = 0x0
    UART = 0x01
    Ethernet = 0x02
    Wifi = 0x03
    Bluetooth = 0x04
    Zigbee = 0x05
    Jtag = 0x06
    SWD = 0x07
    I2C = 0x08
    SPI = 0x09
    TPM = 0x0A


class Peripheral(BaseModel):
    """Base class for all peripherals
    
    Examples:
        >>> p = Peripheral()
        >>> p.name = "MyPeripheral"
        >>> p.pType = PeripheralType.UART
        >>> p.pins = {"tx": "P1", "rx": "P2", "gnd": "GND"}
        >>> print(p)
        name='MyPeripheral' pins={'tx': 'P1', 'rx': 'P2', 'gnd': 'GND'} pType=<PeripheralType.UART: 1>

    Attributes:
        name (str): Name of the peripheral
        pins (Dict[Any, Any]): Dictionary of pin names to their values
        pType (PeripheralType): Type of the peripheral    
    """
    def __init__(
        self,
        name: str = "",
        pins: Dict[Any, Any] | None = None,
        pType: PeripheralType | str | int = PeripheralType.Unknown,
    ) -> None:
        self.name = name
        self.pins = dict(pins) if pins else {}
        if isinstance(pType, PeripheralType):
            self.pType = pType
        elif isinstance(pType, str):
            try:
                self.pType = PeripheralType[pType]
            except KeyError:
                self.pType = PeripheralType.Unknown
        elif isinstance(pType, int):
            try:
                self.pType = PeripheralType(pType)
            except ValueError:
                self.pType = PeripheralType.Unknown
        else:
            self.pType = PeripheralType.Unknown


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
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.UART,
        baudrate: int = 9600,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: int = 1,
        comPort: str = "",
    ) -> None:
        self.tx = ""
        self.rx = ""
        self.gnd = ""
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.pType = pType
        self.com_port = (
            comPort  # Port connected to the user's device to speak to the UART
        )
        if pins:
            self.tx = pins["tx"]
            self.rx = pins["rx"]
            self.gnd = pins["gnd"]

        super().__init__(name, pins, pType)


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
        >>> pins = {"mosi": "P1", "miso": "P2", "sclk": "P3", "gnd": "GND", "cs": "P4", "rst": "P5", "pirq": "P6", "vcc": "VCC"}
        >>> tpm = TPM(name="tpm1", pins=pins)
        >>> print(tpm)
        name='tpm1' pins={'mosi': 'P1', 'miso': 'P2', 'sclk': 'P3', 'gnd': 'GND', 'cs': 'P4', 'rst': 'P5', 'pirq': 'P6', 'vcc': 'VCC'} pType=<PeripheralType.TPM: 10>
        >>> print(tpm.mosi, tpm.miso, tpm.sclk, tpm.gnd, tpm.cs, tpm.rst, tpm.pirq, tpm.vcc)
        P1 P2 P3 GND P4 P5 P6 VCC

    Attributes:
        name (str): Name of the peripheral
        pins (Dict[Any, Any]): Dictionary of pin names to their values
        pType (PeripheralType): Type of the peripheral
        mosi (str): Pin name for MOSI
        miso (str): Pin name for MISO
        sclk (str): Pin name for SCLK
        gnd (str): Pin name for GND
        cs (str): Pin name for CS
        rst (str): Pin name for RST
        pirq (str): Pin name for PIRQ
        vcc (str): Pin name for VCC    
    """

    def __init__(
        self,
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.TPM,
    ) -> None:
        """Initialize TPM peripheral with pin mappings and type.
        
        Args:
            name (str): Name of the TPM peripheral.
            pins (Dict[Any, Any]): Dictionary mapping pin names to their values.
            pType (PeripheralType): Type of the peripheral, defaults to PeripheralType.TPM. 
        """
        self.mosi: str = ""
        self.miso: str = ""
        self.sclk: str = ""
        self.gnd: str = ""
        self.cs: str = ""
        self.rst: str = ""
        self.pirq: str = ""
        self.vcc: str = ""
        self.pType = pType
        if pins:
            self.mosi = pins["mosi"] if pins["mosi"] else ""
            self.miso = pins["miso"] if pins["miso"] else ""
            self.sclk = pins["sclk"] if pins["sclk"] else ""
            self.gnd = pins["gnd"] if pins["gnd"] else ""
            self.cs = pins["cs"] if pins["cs"] else ""
            self.rst = pins["rst"] if pins["rst"] else ""
            self.pirq = pins["pirq"] if pins["pirq"] else ""
            self.vcc = pins["vcc"] if pins["vcc"] else ""

        super().__init__(name, pins, pType)

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
