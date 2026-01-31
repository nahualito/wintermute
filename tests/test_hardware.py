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

# FIX: Import PeripheralType directly from basemodels to satisfy mypy re-export checks
from wintermute.basemodels import PeripheralType
from wintermute.hardware import Architecture, Processor
from wintermute.peripherals import TPM, UART


def test_processor_architecture_initialization() -> None:
    arch = Architecture(core="Cortex-M4", instruction_set="Thumb-2", cpu_cores=1)

    proc = Processor(
        processor="STM32F4", manufacturer="ST", architecture=arch, endianness="little"
    )

    assert proc.processor == "STM32F4"

    # FIX: Type narrowing for mypy (Architecture | Dict | None)
    assert proc.architecture is not None
    assert isinstance(proc.architecture, Architecture)
    assert proc.architecture.core == "Cortex-M4"


def test_uart_peripheral() -> None:
    pins = {"tx": "PA9", "rx": "PA10"}
    uart = UART(name="uart1", pins=pins, baudrate=115200)

    assert uart.name == "uart1"
    assert uart.pType == PeripheralType.UART
    assert uart.baudrate == 115200
    assert uart.pins["tx"] == "PA9"


def test_tpm_packet_generation() -> None:
    tpm = TPM(name="tpm0")

    # Test Request Header generation (Tag, Len, Code)
    # Tag=0x00C1 (Command), Len=10, Ordinal=0x000000AA
    header = tpm._tpm_input_header(0x00C1, 10, 0xAA)

    assert len(header) == 10
    # struct.pack(">HII") -> Big Endian
    # 00 C1 00 00 00 0A 00 00 00 AA
    expected = b"\x00\xc1\x00\x00\x00\n\x00\x00\x00\xaa"
    assert header == expected


def test_tpm_extend_body() -> None:
    tpm = TPM(name="tpm0")
    dummy_digest = b"A" * 20
    pcr_index = 5

    body = tpm._tpm_pcr_extend_req_body(pcr_index, dummy_digest)

    # 4 bytes Int (PCR) + 20 bytes Digest = 24 bytes
    assert len(body) == 24
    assert body.startswith(b"\x00\x00\x00\x05")  # PCR 5 in Big Endian
