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

import os
from pathlib import Path

import pytest

from wintermute.cartridges import firmware_analysis as fa_module
from wintermute.cartridges.firmware_analysis import (
    HIGH_ENTROPY_THRESHOLD,
    BaseAddressAnalysisResult,
    FirmwareAnalysisCartridge,
    analyze_entropy,
    extract_strings,
    scan_for_secrets,
)

# AES forward S-box (full 256 bytes) — used by tests so we have a realistic
# crypto blob, not just the 16-byte detector prefix.
_AES_SBOX_FULL = bytes.fromhex(
    "637c777bf26b6fc5300167 2bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509"
    "832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0ef"
    "aafb434d338545f9027f503c9fa8 51a3408f929d38f5bcb6da2110fff3d2cd0c1"
    "3ec5f974417c8e9197a4172c40a8 4af417c44ed4a727bd8b8a703edf6f4ce2a83"
    "f5c0a4ddc9e76a47f110ce15ce80 c6e9d54a96b4c98e87e9ce5528df8ca189".replace(" ", "")
)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


# ---------------------------------------------------------------------------
# analyze_entropy
# ---------------------------------------------------------------------------


def test_analyze_entropy_all_zeros(tmp_path: Path) -> None:
    blob = _write(tmp_path, "zeros.bin", b"\x00" * 4096)
    result = analyze_entropy(str(blob))

    assert result["file_size_bytes"] == 4096
    assert result["overall_entropy"] == 0.0
    assert result["is_likely_encrypted_or_compressed"] is False
    assert result["high_entropy_blocks"] == []
    assert result["high_entropy_block_count"] == 0


def test_analyze_entropy_uniform_bytes_max_out_at_eight(tmp_path: Path) -> None:
    # bytes(range(256)) is a perfect uniform distribution -> entropy = 8.0.
    blob = _write(tmp_path, "uniform.bin", bytes(range(256)) * 16)
    result = analyze_entropy(str(blob))

    assert result["overall_entropy"] == pytest.approx(8.0)
    assert result["is_likely_encrypted_or_compressed"] is True
    # Every 256-byte block is a permutation of 0..255 -> all blocks high.
    assert result["high_entropy_block_count"] == 1
    assert result["high_entropy_blocks"][0] == {
        "start_offset": "0x0",
        "end_offset": "0x1000",
    }


def test_analyze_entropy_mixed_low_then_high(tmp_path: Path) -> None:
    low = b"\x00" * 4096
    high = bytes(range(256)) * 16  # 4096 bytes
    blob = _write(tmp_path, "mixed.bin", low + high)

    result = analyze_entropy(str(blob))

    assert result["high_entropy_block_count"] == 1
    assert result["high_entropy_blocks"][0] == {
        "start_offset": hex(len(low)),
        "end_offset": hex(len(low) + len(high)),
    }
    # Mixed file: half bytes are 0x00 (highly probable), so entropy is below 8
    # but still well above zero.
    assert 0.5 < result["overall_entropy"] < 8.0


def test_analyze_entropy_threshold_is_strict_inequality(tmp_path: Path) -> None:
    # Half-and-half of two byte values is exactly 1 bit of entropy — well
    # below 7.5, confirming low entropy data is not flagged.
    blob = _write(tmp_path, "binary.bin", (b"\x00\xff") * 1024)
    result = analyze_entropy(str(blob))

    assert result["overall_entropy"] == pytest.approx(1.0)
    assert result["is_likely_encrypted_or_compressed"] is False
    assert result["high_entropy_block_count"] == 0


def test_analyze_entropy_block_size_validation(tmp_path: Path) -> None:
    blob = _write(tmp_path, "x.bin", b"x")
    with pytest.raises(ValueError):
        analyze_entropy(str(blob), block_size=0)


def test_analyze_entropy_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        analyze_entropy("/nonexistent/path/firmware.bin")


def test_analyze_entropy_respects_high_threshold_constant() -> None:
    # Sanity check: the threshold is 7.5 bits/byte.
    assert HIGH_ENTROPY_THRESHOLD == 7.5


def test_analyze_entropy_custom_block_size(tmp_path: Path) -> None:
    # A single perfectly uniform 1024-byte block.
    payload = bytes(range(256)) * 4
    blob = _write(tmp_path, "uniform-1k.bin", payload)
    result = analyze_entropy(str(blob), block_size=1024)

    assert result["block_size"] == 1024
    assert result["overall_entropy"] == pytest.approx(8.0)
    assert result["high_entropy_block_count"] == 1


# ---------------------------------------------------------------------------
# scan_for_secrets
# ---------------------------------------------------------------------------


def test_scan_for_secrets_empty_file(tmp_path: Path) -> None:
    blob = _write(tmp_path, "empty.bin", b"")
    result = scan_for_secrets(str(blob))

    assert result["matches"] == {}
    assert result["total_matches"] == 0
    assert result["truncated"] is False


def test_scan_for_secrets_finds_aes_sbox_with_correct_offset(
    tmp_path: Path,
) -> None:
    padding_left = b"\x90" * 100
    padding_right = b"\x91" * 100
    payload = padding_left + _AES_SBOX_FULL + padding_right
    blob = _write(tmp_path, "aes.bin", payload)

    result = scan_for_secrets(str(blob))

    assert "aes_sbox" in result["matches"]
    assert result["matches"]["aes_sbox"] == [hex(len(padding_left))]


def test_scan_for_secrets_finds_pem_block(tmp_path: Path) -> None:
    pem = (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdz\n"
        b"-----END OPENSSH PRIVATE KEY-----\n"
    )
    blob = _write(tmp_path, "pem.bin", b"\x00" * 32 + pem + b"\x00" * 32)
    result = scan_for_secrets(str(blob))

    assert "pem_block" in result["matches"]
    assert result["matches"]["pem_block"] == [hex(32)]


def test_scan_for_secrets_finds_aws_access_key(tmp_path: Path) -> None:
    needle = b"AKIAIOSFODNN7EXAMPLE"
    # Realistic placement: AWS keys typically sit between non-word characters
    # (quotes, whitespace, NULs in stripped binaries).
    payload = b'aws_key="' + needle + b'"\x00\x00\x00'
    blob = _write(tmp_path, "aws.bin", payload)

    result = scan_for_secrets(str(blob))

    assert "aws_access_key" in result["matches"]
    assert result["matches"]["aws_access_key"] == [hex(payload.find(needle))]


def test_scan_for_secrets_finds_backdoor_keyword(tmp_path: Path) -> None:
    payload = b"the magic_password is hunter2"
    blob = _write(tmp_path, "bd.bin", payload)

    result = scan_for_secrets(str(blob))

    assert "backdoor_keyword" in result["matches"]
    assert result["matches"]["backdoor_keyword"][0] == hex(
        payload.find(b"magic_password")
    )


def test_scan_for_secrets_finds_hardcoded_shell(tmp_path: Path) -> None:
    payload = b"/usr/sbin/init\x00/bin/sh -c reboot\x00"
    blob = _write(tmp_path, "shell.bin", payload)

    result = scan_for_secrets(str(blob))

    assert "hardcoded_shell" in result["matches"]
    assert result["matches"]["hardcoded_shell"] == [hex(payload.find(b"/bin/sh"))]


def test_scan_for_secrets_handles_chunk_boundary(tmp_path: Path) -> None:
    # Place an AES s-box prefix straddling the 64KiB chunk boundary so the
    # overlap-handling logic is exercised.
    chunk_size = 64 * 1024
    leading = b"\x00" * (chunk_size - 8)
    payload = leading + _AES_SBOX_FULL + b"\x00" * 1024
    blob = _write(tmp_path, "boundary.bin", payload)

    result = scan_for_secrets(str(blob))

    assert "aes_sbox" in result["matches"]
    assert result["matches"]["aes_sbox"] == [hex(len(leading))]


def test_scan_for_secrets_dedupes_chunk_boundary_matches(
    tmp_path: Path,
) -> None:
    chunk_size = 64 * 1024
    # PEM marker placed entirely within the first chunk but very close to
    # the boundary, so the next iteration's overlap window also sees it.
    pem = b"-----BEGIN CERTIFICATE-----"
    leading = b"\x00" * (chunk_size - len(pem) - 4)
    payload = leading + pem + b"\x00" * (chunk_size + 1024)
    blob = _write(tmp_path, "boundary-pem.bin", payload)

    result = scan_for_secrets(str(blob))

    assert result["matches"]["pem_block"] == [hex(len(leading))]


def test_scan_for_secrets_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        scan_for_secrets("/nonexistent/path/firmware.bin")


# ---------------------------------------------------------------------------
# extract_strings
# ---------------------------------------------------------------------------


def test_extract_strings_basic_counts(tmp_path: Path) -> None:
    payload = (
        b"\x00\x00helloworld\x00\x00"
        b"AnotherString\x00"
        b"short\x00"  # below default min_length of 8
        b"helloworld\x00"  # duplicate
    )
    blob = _write(tmp_path, "strings.bin", payload)
    result = extract_strings(str(blob))

    assert result["min_length"] == 8
    assert result["total_strings_found"] == 3
    assert result["unique_strings"] == 2


def test_extract_strings_top_20_prioritizes_keywords(tmp_path: Path) -> None:
    payload = (
        b"\x00boring_string_one\x00"
        b"\x00boring_string_two\x00"
        b"\x00admin:password\x00"  # 2 keywords (admin + password)
        b"\x00rooted_device_log\x00"  # 1 keyword (root)
        b"\x00http://example.com/login\x00"  # 1 keyword (http)
        b"\x00format string %s here\x00"  # 1 keyword (%s)
        b"\x00/bin/sh -c id\x00"  # 1 keyword (/bin/sh)
    )
    blob = _write(tmp_path, "interesting.bin", payload)
    result = extract_strings(str(blob), min_length=8)

    top = result["top_20_interesting_strings"]
    assert "admin:password" in top
    assert "rooted_device_log" in top
    assert "http://example.com/login" in top
    assert "format string %s here" in top
    assert "/bin/sh -c id" in top
    # The 2-keyword string should rank first.
    assert top[0] == "admin:password"
    # Boring strings without keywords are excluded.
    assert "boring_string_one" not in top
    assert "boring_string_two" not in top


def test_extract_strings_top_20_caps_results(tmp_path: Path) -> None:
    interesting_template = "admin_panel_user_{n}_password"
    parts = [
        b"\x00" + interesting_template.format(n=i).encode("ascii") + b"\x00"
        for i in range(30)
    ]
    blob = _write(tmp_path, "many.bin", b"".join(parts))
    result = extract_strings(str(blob))

    assert len(result["top_20_interesting_strings"]) == 20


def test_extract_strings_min_length_validation(tmp_path: Path) -> None:
    blob = _write(tmp_path, "x.bin", b"hello there")
    with pytest.raises(ValueError):
        extract_strings(str(blob), min_length=0)


def test_extract_strings_min_length_filter(tmp_path: Path) -> None:
    payload = b"\x00abc\x00abcd\x00abcde\x00abcdef\x00"
    blob = _write(tmp_path, "filter.bin", payload)
    result = extract_strings(str(blob), min_length=5)

    assert result["min_length"] == 5
    assert result["total_strings_found"] == 2
    assert result["unique_strings"] == 2


def test_extract_strings_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        extract_strings("/nonexistent/path/firmware.bin")


# ---------------------------------------------------------------------------
# Cartridge wrapper
# ---------------------------------------------------------------------------


def test_cartridge_delegates_to_module_functions(tmp_path: Path) -> None:
    cartridge = FirmwareAnalysisCartridge()
    blob = _write(tmp_path, "tiny.bin", b"\x00" * 256 + b"admin:password")

    entropy = cartridge.analyze_entropy(str(blob))
    secrets = cartridge.scan_for_secrets(str(blob))
    strings = cartridge.extract_strings(str(blob), min_length=4)

    assert entropy["file_path"].endswith("tiny.bin")
    assert isinstance(secrets["matches"], dict)
    assert "admin:password" in strings["top_20_interesting_strings"]


# ---------------------------------------------------------------------------
# find_base_address (basefind integration)
# ---------------------------------------------------------------------------


class _FakeFWBasefind:
    """Stand-in for FWBasefind that records its config and yields a fixed
    scoring list — keeps the test fast and deterministic without spinning up
    the real multiprocessing scan."""

    captured: list["_FakeFWBasefind"] = []

    def __init__(self, filepath: str, config: object) -> None:
        self.filepath = filepath
        self.config = config
        _FakeFWBasefind.captured.append(self)

    def run(self) -> list[tuple[int, int]]:
        # Deliberately unsorted and longer than 5 entries so the wrapper has
        # to sort + truncate.
        return [
            (0x40000000, 12),
            (0x10000000, 99),
            (0x20000000, 7),
            (0x30000000, 42),
            (0x80000000, 200),
            (0x90000000, 1),
            (0xA0000000, 55),
        ]


@pytest.fixture()
def fake_basefind(monkeypatch: pytest.MonkeyPatch) -> type[_FakeFWBasefind]:
    _FakeFWBasefind.captured.clear()
    monkeypatch.setattr(fa_module, "FWBasefind", _FakeFWBasefind)
    return _FakeFWBasefind


def test_find_base_address_truncates_to_top_5(
    tmp_path: Path, fake_basefind: type[_FakeFWBasefind]
) -> None:
    blob = _write(tmp_path, "fw.bin", b"\x00" * 1024)
    cartridge = FirmwareAnalysisCartridge()

    result = cartridge.find_base_address(str(blob))

    # Validate the schema by re-instantiating the Pydantic model.
    BaseAddressAnalysisResult.model_validate(result)

    # Wrapper sorts highest-score-first and keeps only 5.
    candidates = result["top_5_candidates"]
    assert list(candidates.keys()) == [
        "0x80000000",
        "0x10000000",
        "0xa0000000",
        "0x30000000",
        "0x40000000",
    ]
    assert list(candidates.values()) == [200, 99, 55, 42, 12]
    assert result["candidates_considered"] == 7


def test_find_base_address_propagates_arch_and_range(
    tmp_path: Path, fake_basefind: type[_FakeFWBasefind]
) -> None:
    blob = _write(tmp_path, "fw.bin", b"\x00" * 1024)
    cartridge = FirmwareAnalysisCartridge()

    result = cartridge.find_base_address(
        str(blob),
        arch="arm",
        min_addr=0x08000000,
        max_addr=0x10000000,
    )

    assert result["scan_range"] == {
        "min_addr": "0x08000000",
        "max_addr": "0x10000000",
    }
    assert result["metadata"]["arch"] == "arm"
    assert result["metadata"]["endian"] == "little"
    assert result["metadata"]["bits"] == "32"

    # FWBasefind was instantiated exactly once with the configured ScanConfig.
    assert len(fake_basefind.captured) == 1
    cfg = fake_basefind.captured[0].config
    assert getattr(cfg, "arch") == "arm"
    assert getattr(cfg, "min_addr") == 0x08000000
    assert getattr(cfg, "max_addr") == 0x10000000
    # Wrapper must keep the host responsive: progress, verbose, and entropy
    # checks all disabled.
    assert getattr(cfg, "verbose") is False
    assert getattr(cfg, "progress") is False
    assert getattr(cfg, "entropy_check") is False


def test_find_base_address_caps_workers_to_half_cpu(
    tmp_path: Path,
    fake_basefind: type[_FakeFWBasefind],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    blob = _write(tmp_path, "fw.bin", b"\x00" * 64)
    cartridge = FirmwareAnalysisCartridge()

    cartridge.find_base_address(str(blob))

    cfg = fake_basefind.captured[0].config
    assert getattr(cfg, "workers") == 4


def test_find_base_address_minimum_one_worker(
    tmp_path: Path,
    fake_basefind: type[_FakeFWBasefind],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Single-CPU host: half of 1 floors to 0; the wrapper must clamp to 1.
    monkeypatch.setattr(os, "cpu_count", lambda: 1)
    blob = _write(tmp_path, "fw.bin", b"\x00" * 64)
    cartridge = FirmwareAnalysisCartridge()

    cartridge.find_base_address(str(blob))

    cfg = fake_basefind.captured[0].config
    assert getattr(cfg, "workers") == 1


def test_find_base_address_handles_empty_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _EmptyFinder(_FakeFWBasefind):
        def run(self) -> list[tuple[int, int]]:
            return []

    _FakeFWBasefind.captured.clear()
    monkeypatch.setattr(fa_module, "FWBasefind", _EmptyFinder)

    blob = _write(tmp_path, "fw.bin", b"\x00" * 64)
    cartridge = FirmwareAnalysisCartridge()
    result = cartridge.find_base_address(str(blob))

    BaseAddressAnalysisResult.model_validate(result)
    assert result["top_5_candidates"] == {}
    assert result["candidates_considered"] == 0


def test_find_base_address_missing_file() -> None:
    cartridge = FirmwareAnalysisCartridge()
    with pytest.raises(FileNotFoundError):
        cartridge.find_base_address("/nonexistent/path/firmware.bin")


def test_find_base_address_rejects_invalid_arch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ScanConfig.validate() runs inside the real FWBasefind.__init__. Use a
    # validating fake to confirm the wrapper actually surfaces a bad arch.
    class _ValidatingFinder(_FakeFWBasefind):
        def __init__(self, filepath: str, config: object) -> None:
            super().__init__(filepath, config)
            getattr(config, "validate")()

    _FakeFWBasefind.captured.clear()
    monkeypatch.setattr(fa_module, "FWBasefind", _ValidatingFinder)

    blob = _write(tmp_path, "fw.bin", b"\x00" * 64)
    cartridge = FirmwareAnalysisCartridge()
    with pytest.raises(ValueError, match="arch"):
        cartridge.find_base_address(str(blob), arch="powerpc")
