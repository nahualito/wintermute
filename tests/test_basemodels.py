# tests/test_basemodels.py
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List

import pytest

from wintermute.basemodels import BaseModel, CloudAccount, Peripheral, PeripheralType

# --------------------------
# Helpers for BaseModel tests
# --------------------------


class Color(Enum):
    RED = "red"
    BLUE = "blue"
    GREEN = "green"


@dataclass(eq=False)  # <- preserve BaseModel.__hash__
class Hashy(BaseModel):
    x: int = 0


@dataclass
class CommentLike(BaseModel):
    author: str
    text: str
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Thing(BaseModel):
    color: Color = Color.RED
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    notes: Dict[str, Any] = field(default_factory=dict)
    children: List[CommentLike] = field(default_factory=list)

    __schema__ = {"children": CommentLike}
    __enums__ = {"color": Color}


@dataclass
class Host(BaseModel):
    ip: ipaddress.IPv4Address
    when: datetime

    __schema__ = {}
    __enums__ = {}


# --------------------------
# BaseModel core behavior
# --------------------------


def test_to_dict_serializes_datetime_enum_ip_and_nested() -> None:
    child = CommentLike(
        author="qa", text="ok", at=datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    )
    t = Thing(
        color=Color.BLUE,
        at=datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc),
        tags=["a", "b"],
        notes={"k": 1},
        children=[child],
    )
    d = t.to_dict()

    # Enum serialized as name by default (per BaseModel._jsonify)
    assert d["color"] in ("BLUE", "RED", "GREEN")
    # Datetime serialized as ISO string with Z
    assert isinstance(d["at"], str) and d["at"].endswith("Z")
    assert isinstance(d["children"][0]["at"], str) and d["children"][0]["at"].endswith(
        "Z"
    )
    # JSON safe
    json.dumps(d)


def test_from_dict_round_trip_enums_by_name_and_value_and_datetime() -> None:
    # color by NAME
    payload1 = {
        "color": "BLUE",
        "at": "2025-10-17T13:00:00Z",
        "tags": ["x"],
        "notes": {"foo": "bar"},
        "children": [{"author": "qa", "text": "hi", "at": "2025-10-17T13:05:00Z"}],
    }
    t1 = Thing.from_dict(payload1)
    assert t1.color is Color.BLUE
    assert isinstance(t1.at, datetime) and t1.at.tzinfo is not None
    assert isinstance(t1.children[0].at, datetime)

    # color by VALUE also works
    payload2 = dict(payload1)
    payload2["color"] = "blue"
    t2 = Thing.from_dict(payload2)
    assert t2.color is Color.BLUE


def test_from_dict_schema_type_errors_on_wrong_child_type() -> None:
    bad = {
        "color": "RED",
        "at": "2025-10-17T13:00:00Z",
        "children": [42],  # not dict, not CommentLike
    }
    with pytest.raises(TypeError):
        Thing.from_dict(bad)


def test_ip_adapter_and_parser_round_trip() -> None:
    h = Host(
        ip=ipaddress.IPv4Address("192.168.1.10"),
        when=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    d = h.to_dict()
    assert d["ip"] == "192.168.1.10"
    assert d["when"].endswith("Z")

    h2 = Host.from_dict(d)
    assert isinstance(h2.ip, ipaddress.IPv4Address)
    assert h2.ip == ipaddress.IPv4Address("192.168.1.10")
    assert isinstance(h2.when, datetime)


def test_eq_and_hash_based_on_to_dict() -> None:
    a1 = Thing(color=Color.GREEN, children=[])
    a2 = Thing.from_dict(a1.to_dict())
    assert a1 == a2

    # Verify BaseModel.__hash__ works using a dataclass that doesn't disable it
    h1 = Hashy(1)
    h2 = Hashy.from_dict(h1.to_dict())
    assert h1 == h2
    assert hash(h1) == hash(h2)


# --------------------------
# Peripheral & CloudAccount
# --------------------------


def test_peripheral_pType_coercion_from_enum_str_int_and_default() -> None:
    # Enum direct
    p_enum = Peripheral(
        device_path="/dev/ttyUSB0", name="Uart", pType=PeripheralType.UART
    )
    assert p_enum.pType is PeripheralType.UART

    # String by name
    p_str = Peripheral(device_path="eth0", name="Eth", pType="Ethernet")
    assert p_str.pType is PeripheralType.Ethernet

    # Unknown string falls back to Unknown
    p_bad = Peripheral(device_path="none", name="Nope", pType="not-a-real-type")
    assert p_bad.pType is PeripheralType.Unknown

    # Integer by value and bad int fallback
    p_int = Peripheral(
        device_path="spi0", name="SPI", pType=int(PeripheralType.SPI.value)
    )
    assert p_int.pType is PeripheralType.SPI

    p_int_bad = Peripheral(device_path="bad", name="BadInt", pType=999)
    assert p_int_bad.pType is PeripheralType.Unknown


def test_cloudaccount_vulnerabilities_type_error_on_invalid_item() -> None:
    # We intentionally pass an invalid type inside vulnerabilities to hit the TypeError path
    with pytest.raises(TypeError):
        CloudAccount(name="acct", vulnerabilities=[123])  # type: ignore[list-item]
