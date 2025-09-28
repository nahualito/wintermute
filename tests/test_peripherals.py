# tests/test_peripherals.py
from __future__ import annotations

import json
from typing import Any, Dict, Type

from wintermute.basemodels import (
    BaseModel,
    Peripheral,
    PeripheralType,
)
from wintermute.peripherals import (
    TPM,
    UART,
    TPM_interposer_commands,
    TPM_register,
)

# ---------------------------
# Helpers (typed)
# ---------------------------


def roundtrip(cls: Type[BaseModel], inst: BaseModel) -> BaseModel:
    """to_dict -> json.dumps -> json.loads -> from_dict, returns new instance"""
    as_dict = inst.to_dict()
    # Ensure JSON-safe
    dumped = json.dumps(as_dict)
    loaded: Dict[str, Any] = json.loads(dumped)
    return cls.from_dict(loaded)


# ---------------------------
# PeripheralType & base class
# ---------------------------


def test_peripheraltype_members_are_enum() -> None:
    assert isinstance(PeripheralType.UART, PeripheralType)
    assert PeripheralType.UART.value == 0x01
    assert PeripheralType.Unknown.value == 0x00


def test_peripheral_defaults_and_roundtrip() -> None:
    p = Peripheral()
    assert p.name == ""
    assert isinstance(p.pType, PeripheralType)
    assert p.pType == PeripheralType.Unknown
    # pins default (dict) should be present as assigned
    assert isinstance(p.pins, dict)

    # round-trip via BaseModel
    p2 = roundtrip(Peripheral, p)
    assert p2.to_dict() == p.to_dict()


def test_peripheral_custom_init_and_roundtrip() -> None:
    pins: Dict[str, Any] = {"A": 1, "B": 2}
    p = Peripheral(name="periph", pins=pins, pType=PeripheralType.Wifi)
    assert p.name == "periph"
    assert p.pins == pins
    assert p.pType == PeripheralType.Wifi

    p2 = roundtrip(Peripheral, p)
    assert p2.to_dict() == p.to_dict()


# ---------------------------
# UART
# ---------------------------


def test_uart_default_values_and_type() -> None:
    u = UART()
    # defaults
    assert u.baudrate == 9600
    assert u.bytesize == 8
    assert u.parity == "N"
    assert u.stopbits == 1
    assert u.pType == PeripheralType.UART
    # default pins empty -> tx/rx/gnd empty strings
    assert u.tx == ""
    assert u.rx == ""
    assert u.gnd == ""

    # BaseModel round-trip
    u2 = roundtrip(UART, u)
    assert u2.to_dict() == u.to_dict()


def test_uart_pin_mapping_and_com_port_roundtrip() -> None:
    pins: Dict[str, Any] = {"tx": "P1", "rx": "P2", "gnd": "GND"}
    u = UART(name="dbg", pins=pins, comPort="/dev/ttyUSB0")
    assert u.pins['tx'] == "P1"
    assert u.pins['rx'] == "P2"
    assert u.pins['gnd'] == "GND"
    assert u.com_port == "/dev/ttyUSB0"
    assert u.pType == PeripheralType.UART

    u2 = roundtrip(UART, u)
    assert u2.to_dict() == u.to_dict()


# ---------------------------
# TPM
# ---------------------------


def _all_tpm_pins() -> Dict[str, Any]:
    # Provide all keys to avoid KeyError in __init__
    return {
        "mosi": "P_MOSI",
        "miso": "P_MISO",
        "sclk": "P_SCLK",
        "gnd": "P_GND",
        "cs": "P_CS",
        "rst": "P_RST",
        "pirq": "P_PIRQ",
        "vcc": "P_VCC",
    }


def test_tpm_pin_mapping_and_type() -> None:
    t = TPM(name="tpm0", pins=_all_tpm_pins())
    assert t.mosi == "P_MOSI"
    assert t.miso == "P_MISO"
    assert t.sclk == "P_SCLK"
    assert t.gnd == "P_GND"
    assert t.cs == "P_CS"
    assert t.rst == "P_RST"
    assert t.pirq == "P_PIRQ"
    assert t.vcc == "P_VCC"
    assert t.pType == PeripheralType.TPM

    t2 = roundtrip(TPM, t)
    assert t2.to_dict() == t.to_dict()


def test_tpm_headers_sizes_and_values() -> None:
    t = TPM()

    # input/output headers are 2 (H) + 4 (I) + 4 (I) = 10 bytes each
    hdr_in = t._tpm_input_header(tag=0xAA55, len=0x12345678, code=0xCAFEBABE)
    hdr_out = t._tpm_output_header(tag=0xAA55, len=0x9ABCDEF0, code=0xFEEDBEEF)
    assert isinstance(hdr_in, (bytes, bytearray))
    assert isinstance(hdr_out, (bytes, bytearray))
    assert len(hdr_in) == 10
    assert len(hdr_out) == 10

    # sanity: first two bytes should equal tag in big-endian
    assert hdr_in[0:2] == b"\xaa\x55"
    assert hdr_out[0:2] == b"\xaa\x55"


def test_tpm_pcr_read_bodies() -> None:
    t = TPM()
    req = t._tpm_pcr_read_req_body(pcr_index=7)
    resp = t._tpm_pcr_read_resp_body(out_digest=b"\x00" * 20)
    assert len(req) == 4  # >I
    assert len(resp) == 20  # >20s


def test_tpm_pcr_extend_bodies() -> None:
    t = TPM()
    req = t._tpm_pcr_extend_req_body(pcr_index=5, in_digest=b"\x11" * 20)
    resp = t._tpm_pcr_extend_resp_body(out_digest=b"\x22" * 20)
    assert len(req) == 24  # >I20s
    assert len(resp) == 20  # >20s


def test_tpm_get_random_bodies() -> None:
    t = TPM()
    req = t._tpm_get_rnd_req_body(num_bytes=64)
    resp = t._tpm_get_rnd_resp_body(random_bytes_size=64, random_bytes=b"\xaa" * 128)
    assert len(req) == 4  # >I
    assert len(resp) == 132  # >I128s


def test_tpm_enums_present() -> None:
    # Just a couple of spot checks
    assert TPM_register.TPM_ACCESS.value == 0x0000
    assert TPM_register.TPM_REG_NONE.value == 0xFFFF
    assert TPM_interposer_commands.TPM_ORD_GetRandom.value == 0x46
    assert TPM_interposer_commands.TSC_ORD_PhysicalPresence.value == 0x4000000A
