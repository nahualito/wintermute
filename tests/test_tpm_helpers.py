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
import struct
import types
from typing import Any, Type

import pytest


def _import_peripherals_module() -> types.ModuleType:
    for name in ("wintermute.peripherals", "peripherals"):
        try:
            return importlib.import_module(name)
        except Exception:  # pragma: no cover
            continue
    raise ImportError("peripherals module not found")


def _get_cls(mod: types.ModuleType, name: str) -> Type[Any]:
    cls = getattr(mod, name, None)
    if not isinstance(cls, type):
        raise AttributeError(f"{name} not found in {mod.__name__}")
    return cls


@pytest.fixture(scope="module")
def TPM(peripherals_mod: types.ModuleType) -> Type[Any]:
    return _get_cls(peripherals_mod, "TPM")


@pytest.fixture(scope="module")
def peripherals_mod() -> types.ModuleType:
    return _import_peripherals_module()


def test_tpm_constructs(TPM: Type[Any]) -> None:
    tpm = TPM(
        name="tpm1", pins={"mosi": "P1", "miso": "P2", "sclk": "P3", "gnd": "GND"}
    )
    assert getattr(tpm, "name") == "tpm1"


def test_tpm_input_header(TPM: Type[Any]) -> None:
    tpm = TPM()
    # Expect big-endian: tag (H), paramSize (I), ordinal (I)
    packed = tpm._tpm_input_header(0x00C1, 30, 0x00000046)
    assert isinstance(packed, (bytes, bytearray))
    assert len(packed) == struct.calcsize(">HII")
    assert packed == struct.pack(">HII", 0x00C1, 30, 0x00000046)


def test_tpm_output_header(TPM: Type[Any]) -> None:
    tpm = TPM()
    # Expect big-endian: tag (H), paramSize (I), returnCode (I)
    packed = tpm._tpm_output_header(0x00C4, 24, 0x00000000)
    assert packed == struct.pack(">HII", 0x00C4, 24, 0x00000000)


def test_tpm_pcr_read_bodies(TPM: type) -> None:
    import struct

    tpm = TPM()
    req = tpm._tpm_pcr_read_req_body(pcr_index=7)
    assert req == struct.pack(">I", 7)

    digest = b"\xaa" * 20

    # Your impl: response body = digest only (no size prefix)
    resp = tpm._tpm_pcr_read_resp_body(digest)

    assert resp == struct.pack(">20s", digest)
    assert len(resp) == 20


def test_tpm_pcr_extend_bodies(TPM: Type[Any]) -> None:
    tpm = TPM()
    # request: pcrIndex (I) + inDigest (20s)
    req = tpm._tpm_pcr_extend_req_body(pcr_index=3, in_digest=b"\x11" * 20)
    assert req == struct.pack(">I20s", 3, b"\x11" * 20)

    # response: outDigest (20s)
    resp = tpm._tpm_pcr_extend_resp_body(out_digest=b"\x22" * 20)
    assert resp == struct.pack(">20s", b"\x22" * 20)


def test_tpm_random_and_auth_bodies(TPM: Type[Any]) -> None:
    tpm = TPM()
    # get random: size (I)
    req_rnd = tpm._tpm_get_rnd_req_body(num_bytes=16)
    assert req_rnd == struct.pack(">I", 16)

    # rnd resp: size (I) + bytes (128s) per code
    rnd = b"\x33" * 16 + b"\x00" * (128 - 16)
    resp_rnd = tpm._tpm_get_rnd_resp_body(random_bytes_size=16, random_bytes=rnd)
    assert resp_rnd == struct.pack(">I128s", 16, rnd)

    # operator auth: 20s
    auth = b"\x44" * 20
    req_auth = tpm._tpm_op_auth_req_body(operator_auth=auth)
    assert req_auth == struct.pack(">20s", auth)
