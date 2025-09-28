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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .findings import Vulnerability  # type-only, no runtime import

import inspect
import ipaddress
import json
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Self, Type


class BaseModel:
    """Base class for all models to provide common functionality.

    This class provides common functionality for all models, including serialization
    to/from dict, equality comparison, and hashing.

    Examples:
        >>> import core
        >>> r = core.Risk(likelihood="High", impact="High", severity="Critical")
        >>> d = r.to_dict()
        >>> d["severity"]
        'Critical'
        >>> r2 = core.Risk.from_dict(d)
        >>> r == r2
        True

    Attributes:
        * __schema__ (dict): Schema defining sub-objects for serialization/deserialization
    """

    __schema__: dict[str, Any] = {}

    JSON_ADAPTERS: Dict[Type[Any], Callable[[Any], Any]] = {
        ipaddress.IPv4Address: str,
        ipaddress.IPv6Address: str,
    }

    @staticmethod
    def _jsonify(value: Any) -> Any:
        """Default recursive serializer used by to_dict()."""
        if isinstance(value, BaseModel):
            return value.to_dict()
        if isinstance(value, list):
            return [BaseModel._jsonify(v) for v in value]
        if isinstance(value, Enum):
            return value.name
        # Built-in adapters
        for typ, adapter in BaseModel.JSON_ADAPTERS.items():
            if isinstance(value, typ):
                return adapter(value)
        # Let subclasses try custom conversions
        extra = BaseModel._jsonify_extra(value)
        if extra is not None:
            return extra
        return value

    @staticmethod
    def _jsonify_extra(value: Any) -> Any:
        """Hook for subclasses to override when they need custom conversions.
        Return None to indicate 'not handled'."""
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k.startswith("_"):
                continue  # skip private/internal fields (e.g., DB handles)
            out[k] = BaseModel._jsonify(v)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for {cls.__name__}, got {type(data)}")

        # 1) Normalize nested fields declared in __schema__ (dicts -> objects, lists -> list[objects])
        normalized: dict[str, Any] = {}
        schema = getattr(cls, "__schema__", {})

        for key, val in data.items():
            if key in schema:
                subcls = schema[key]
                if isinstance(val, list):
                    out_list = []
                    for v in val:
                        if isinstance(v, dict):
                            out_list.append(subcls.from_dict(v))
                        elif isinstance(v, subcls):
                            out_list.append(v)
                        else:
                            raise TypeError(
                                f"Unexpected type in list for {key}: {type(v)}"
                            )
                    normalized[key] = out_list
                elif isinstance(val, dict):
                    normalized[key] = subcls.from_dict(val)
                elif isinstance(val, subcls):
                    normalized[key] = val
                else:
                    raise TypeError(f"Unexpected type for {key}: {type(val)}")
            else:
                normalized[key] = val

        # 2) Only pass kwargs that the constructor actually accepts
        sig = inspect.signature(cls)
        accepted_names = {
            p.name
            for p in sig.parameters.values()
            if p.kind
            in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        }
        ctor_kwargs = {k: v for k, v in normalized.items() if k in accepted_names}

        # 3) Construct
        obj = cls(**ctor_kwargs)

        # 4) Set any remaining fields (derived attrs like tx/rx/gnd, mosi/miso/etc.)
        for k, v in normalized.items():
            if k not in ctor_kwargs:
                setattr(obj, k, v)

        return obj

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and self.to_dict() == other.to_dict()

    def __hash__(self) -> int:
        return hash(json.dumps(self.to_dict(), sort_keys=True))


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

    __schema__ = {
        "vulnerabilities": "Vulnerability",
    }

    def __init__(
        self,
        name: str = "",
        pins: Dict[Any, Any] | None = None,
        pType: PeripheralType | str | int = PeripheralType.Unknown,
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.name = name
        self.pins = dict(pins) if pins else {}

        from .findings import Vulnerability as _Vulnerability

        self.vulnerabilities: List[_Vulnerability] = []
        if vulnerabilities:
            for v in vulnerabilities:
                if isinstance(v, _Vulnerability):
                    self.vulnerabilities.append(v)
                elif isinstance(v, dict):
                    self.vulnerabilities.append(_Vulnerability.from_dict(v))
                else:
                    raise TypeError(
                        f"Unexpected type in vulnerabilities list: {type(v)}"
                    )
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


class CloudAccount(BaseModel):
    """Class representing a cloud account."""

    __schema__ = {
        "vulnerabilities": "Vulnerability",
    }

    def __init__(
        self,
        name: str,
        description: str = "",
        *,
        vulnerabilities: Optional[List[Vulnerability | dict[str, Any]]] = None,
    ) -> None:
        self.name = name
        self.description = description
        from .findings import Vulnerability as _Vulnerability

        self.vulnerabilities: List[_Vulnerability] = []
        if vulnerabilities:
            for v in vulnerabilities:
                if isinstance(v, _Vulnerability):
                    self.vulnerabilities.append(v)
                elif isinstance(v, dict):
                    self.vulnerabilities.append(_Vulnerability.from_dict(v))
                else:
                    raise TypeError(
                        f"Unexpected type in vulnerabilities list: {type(v)}"
                    )
