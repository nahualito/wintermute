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
Base models for Wintermute
--------------------------
This file contains the base models used throughout Wintermute, including
serialization and deserialization logic with support for enums, datetimes,
and IP addresses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .findings import Vulnerability  # type-only, no runtime import

import inspect
import ipaddress
import json
import sys
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Self, Type


class BaseModel:
    """Common serialize/deserialize with adapters & parsers (enum/datetime/IP support)."""

    __schema__: dict[
        str, Any
    ] = {}  # field -> BaseModel subclass for nested objects/lists
    __enums__: dict[
        str, Type[Enum]
    ] = {}  # field -> Enum class (for coercion on from_dict)

    # --- Serialization adapters (objects -> JSON scalars) ---
    JSON_ADAPTERS: Dict[Type[Any], Callable[[Any], Any]] = {
        ipaddress.IPv4Address: str,
        ipaddress.IPv6Address: str,
        datetime: lambda dt: dt.isoformat().replace("+00:00", "Z")
        if dt.tzinfo
        else dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    # --- Deserialization parsers (JSON scalars -> objects) ---
    PARSERS: Dict[Type[Any], Callable[[Any], Any]] = {
        datetime: lambda s: datetime.fromisoformat(str(s).replace("Z", "+00:00")),
        ipaddress.IPv4Address: lambda s: ipaddress.ip_address(s),
        ipaddress.IPv6Address: lambda s: ipaddress.ip_address(s),
    }

    # ---------- to_dict ----------
    @staticmethod
    def _jsonify(value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.to_dict()
        if is_dataclass(
            value
        ):  # recurse so dataclass fields (e.g., datetime) are adapted
            return {
                f.name: BaseModel._jsonify(getattr(value, f.name))
                for f in fields(value)
            }
        if isinstance(value, list):
            return [BaseModel._jsonify(v) for v in value]
        if isinstance(value, Enum):
            return (
                value.name
            )  # flip to .value if you prefer the enum values instead of names
        for typ, adapter in BaseModel.JSON_ADAPTERS.items():
            if isinstance(value, typ):
                return adapter(value)
        extra = BaseModel._jsonify_extra(value)
        if extra is not None:
            return extra
        return value

    @staticmethod
    def _jsonify_extra(value: Any) -> Any:
        """Subclass hook: return a JSON-safe object or None to skip."""
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k.startswith("_"):
                continue
            out[k] = BaseModel._jsonify(v)
        return out

    # ---------- from_dict ----------
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for {cls.__name__}, got {type(data)}")

        schema: dict[str, Any] = getattr(cls, "__schema__", {})
        enums: dict[str, type[Enum]] = getattr(cls, "__enums__", {})

        # <<< use resolved type hints (handles future-annotations and forward refs)
        from typing import Union, get_args, get_origin, get_type_hints

        ann: dict[str, Any] = get_type_hints(cls)

        def _resolve_target_type(t: Any) -> type[Any] | None:
            # already a concrete class?
            if isinstance(t, type):
                return t
            origin = get_origin(t)
            if origin is None:
                return None
            # Optional/Union[...] → pick the first concrete class (e.g., datetime)
            if origin is Union:
                for arg in get_args(t):
                    if isinstance(arg, type):
                        return arg
                return None
            return None

        def coerce_scalar(key: str, val: Any) -> Any:
            if val is None:
                return None
            # Enums (opt-in via __enums__)
            if key in enums:
                et = enums[key]
                if isinstance(val, et):
                    return val
                if isinstance(val, str):
                    try:
                        return et[val]  # by NAME
                    except KeyError:
                        for m in et:
                            if m.value == val:  # by VALUE
                                return m
                raise TypeError(
                    f"Cannot coerce {val!r} to {et.__name__} for field {key}"
                )

            # Parsers (datetime, IPs, etc.) based on resolved annotation
            target = _resolve_target_type(ann.get(key))
            if target is not None:
                parser = BaseModel.PARSERS.get(target)
                if parser is not None and not isinstance(val, target):
                    return parser(val)

            return val

        # 1) Normalize nested fields and coerce direct scalars
        normalized: dict[str, Any] = {}
        for key, val in data.items():
            if key in schema:
                subcls = schema[key]
                if isinstance(subcls, str):
                    resolved: object | None = None

                    # Prefer resolving from type hints (already get_type_hints(cls) above)
                    hinted = ann.get(key)
                    if hinted is not None:
                        origin = get_origin(hinted)
                        args = get_args(hinted)

                        # list[T] / set[T] / tuple[T,...]
                        if origin in (list, set, tuple) and args:
                            if isinstance(args[0], type):
                                resolved = args[0]
                        # direct T
                        elif isinstance(hinted, type):
                            resolved = hinted

                    # Fallback: resolve from the module where cls is defined
                    if resolved is None:
                        mod = sys.modules.get(cls.__module__)
                        if mod is not None and hasattr(mod, subcls):
                            cand = getattr(mod, subcls)
                            if isinstance(cand, type):
                                resolved = cand

                    if resolved is None:
                        raise TypeError(
                            f"Could not resolve schema type '{subcls}' for field '{key}' on {cls.__name__}"
                        )

                    subcls = resolved
                if val is None:
                    normalized[key] = None
                    continue

                if isinstance(val, list):
                    out_list: list[Any] = []
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
                normalized[key] = coerce_scalar(key, val)

        # 2) Filter kwargs to __init__
        sig = inspect.signature(cls)
        accepted = {
            p.name
            for p in sig.parameters.values()
            if p.kind
            in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        }
        ctor_kwargs = {k: v for k, v in normalized.items() if k in accepted}

        # 3) Construct
        obj = cls(**ctor_kwargs)

        # 4) Set remaining attributes
        for k, v in normalized.items():
            if k not in ctor_kwargs:
                setattr(obj, k, v)

        # 5) Final safety pass: coerce any annotated scalars left as strings/etc.
        for k, annot in ann.items():
            if not hasattr(obj, k):
                continue
            cur = getattr(obj, k)
            if cur is None:
                continue
            # skip nested/containers
            if isinstance(cur, (BaseModel, list, dict)):
                continue

            # Enums again if needed
            if k in enums and isinstance(cur, str):
                et = enums[k]
                try:
                    setattr(obj, k, et[cur])  # by NAME
                    continue
                except KeyError:
                    for m in et:
                        if m.value == cur:  # by VALUE
                            setattr(obj, k, m)
                            break
                    continue

            # Parsers again with resolved type
            target = _resolve_target_type(annot)
            if target is not None:
                parser = BaseModel.PARSERS.get(target)
                if parser is not None and not isinstance(cur, target):
                    try:
                        setattr(obj, k, parser(cur))
                    except Exception:
                        pass

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
    JTAG = 0x06
    SWD = 0x07
    I2C = 0x08
    SPI = 0x09
    TPM = 0x0A
    USB = 0x0B


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
        workspace: str = "",
    ) -> None:
        self.name = name
        self.pins = dict(pins) if pins else {}
        self.workspace = workspace

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


# Fixes
from .findings import Vulnerability  # noqa: E402
