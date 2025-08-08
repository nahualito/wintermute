# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long

"""
Peripherals classes for onoSendai
----------------------------------

This file contains the peripheral metaclass and the classes that inherit from it
to give access to hardware peripherals and have more abstraction for automation
and attacking.
"""

import json
import struct
from enum import Enum
from typing import Any, Dict


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


class Peripheral:
    def __init__(
        self,
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.Unknown,
    ) -> None:
        self.name = name
        self.pins = pins
        self.pType = pType
        pass

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class UART(Peripheral):
    """Class that defines the UART interface"""

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
    """Class that defines a TPM peripheral"""

    def __init__(
        self,
        name: str = "",
        pins: Dict[Any, Any] = {},
        pType: PeripheralType = PeripheralType.TPM,
    ) -> None:
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
