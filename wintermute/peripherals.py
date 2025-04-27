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
        self.com_port = (
            comPort  # Port connected to the user's device to speak to the UART
        )
        if pins:
            self.tx = pins["tx"]
            self.rx = pins["rx"]
            self.gnd = pins["gnd"]

        super().__init__(name, pins, pType)
