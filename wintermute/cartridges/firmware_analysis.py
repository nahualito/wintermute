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

import logging
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Final, List, Tuple

from pydantic import BaseModel, Field

from wintermute.utils.basefind import FWBasefind, ScanConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


HIGH_ENTROPY_THRESHOLD: Final[float] = 7.5
"""Per Shannon, log2(256) = 8 is the maximum entropy of a uniformly random byte
stream. 7.5 is the de facto industry threshold for flagging
encrypted/compressed regions in firmware."""

INTERESTING_STRING_KEYWORDS: Final[Tuple[str, ...]] = (
    "http",
    "admin",
    "root",
    "password",
    "%s",
    "/bin/sh",
)

_STREAM_CHUNK_SIZE: Final[int] = 64 * 1024
_SECRET_OVERLAP: Final[int] = 256
_MAX_OFFSETS_PER_TYPE: Final[int] = 64
_TOP_INTERESTING_STRINGS: Final[int] = 20
_TOP_BASE_CANDIDATES: Final[int] = 5


# Well-known cryptographic constants. Detecting the leading bytes of each is
# enough: the false-positive rate is bounded by (1/2^N) for N random bytes, so
# 16-byte prefixes are effectively unique.
_AES_SBOX_PREFIX: Final[bytes] = bytes.fromhex(
    "637c777bf26b6fc5300167 2bfed7ab76".replace(" ", "")
)
_AES_INVERSE_SBOX_PREFIX: Final[bytes] = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb"
)
_DES_SBOX_S1: Final[bytes] = bytes.fromhex("0e040d01020f0b08030a060c05090007")
_SHA256_INITIAL_HASH: Final[bytes] = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a")
_MD5_INITIAL_HASH: Final[bytes] = bytes.fromhex("0123456789abcdeffedcba9876543210")


_BYTE_PATTERNS: Final[Tuple[Tuple[str, bytes], ...]] = (
    ("aes_sbox", _AES_SBOX_PREFIX),
    ("aes_inverse_sbox", _AES_INVERSE_SBOX_PREFIX),
    ("des_sbox_s1", _DES_SBOX_S1),
    ("sha256_initial_hash", _SHA256_INITIAL_HASH),
    ("md5_initial_hash", _MD5_INITIAL_HASH),
)


_TEXT_PATTERNS: Final[Tuple[Tuple[str, "re.Pattern[bytes]"], ...]] = (
    ("pem_block", re.compile(rb"-----BEGIN [A-Z0-9 ]{3,40}-----")),
    (
        "ssh_public_key",
        re.compile(rb"ssh-(?:rsa|ed25519|dss) AAAA[A-Za-z0-9+/=]{20,}"),
    ),
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    (
        "backdoor_keyword",
        re.compile(
            rb"(?i)\b(?:backdoor|debug_password|hardcoded[ _-]?password|"
            rb"magic[ _-]?password)\b"
        ),
    ),
    ("hardcoded_shell", re.compile(rb"/bin/(?:sh|bash|ash|dash)\b")),
)


# ---------------------------------------------------------------------------
# Pydantic result models
# ---------------------------------------------------------------------------


class EntropyBlock(BaseModel):
    """A contiguous stretch of file content whose chunks exceeded the
    high-entropy threshold."""

    start_offset: str
    end_offset: str


class EntropyAnalysisResult(BaseModel):
    """Structured output for :func:`analyze_entropy`."""

    file_path: str
    file_size_bytes: int = Field(ge=0)
    block_size: int = Field(ge=1)
    overall_entropy: float = Field(ge=0.0, le=8.0)
    is_likely_encrypted_or_compressed: bool
    high_entropy_blocks: List[EntropyBlock]
    high_entropy_block_count: int = Field(ge=0)


class SecretScanResult(BaseModel):
    """Structured output for :func:`scan_for_secrets`."""

    file_path: str
    file_size_bytes: int = Field(ge=0)
    matches: dict[str, list[str]]
    total_matches: int = Field(ge=0)
    truncated: bool


class StringExtractionResult(BaseModel):
    """Structured output for :func:`extract_strings`."""

    file_path: str
    file_size_bytes: int = Field(ge=0)
    min_length: int = Field(ge=1)
    total_strings_found: int = Field(ge=0)
    unique_strings: int = Field(ge=0)
    top_20_interesting_strings: List[str]


class BaseAddressAnalysisResult(BaseModel):
    """Structured output for :meth:`FirmwareAnalysisCartridge.find_base_address`.

    Mirrors the shape of the other analysis result models: a flat dict suitable
    for JSON serialisation back to the LLM, with the heavy raw scoring array
    deliberately replaced by the top 5 candidates.
    """

    file_path: str
    file_size_bytes: int = Field(ge=0)
    scan_range: dict[str, str]
    top_5_candidates: dict[str, int]
    candidates_considered: int = Field(ge=0)
    metadata: dict[str, str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_file(file_path: str) -> Path:
    """Resolve and validate the supplied file path."""
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {path}")
    return path


def _shannon_entropy(counts: "Counter[int]", total: int) -> float:
    """Compute Shannon entropy in bits-per-byte from an aggregate byte count."""
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _interest_score(value: str) -> int:
    """Count how many sentinel keywords appear in ``value``."""
    lowered = value.lower()
    return sum(1 for keyword in INTERESTING_STRING_KEYWORDS if keyword in lowered)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def analyze_entropy(file_path: str, block_size: int = 256) -> dict[str, Any]:
    """Compute Shannon entropy across a firmware blob and flag suspicious regions.

    Walks the file in fixed-size chunks, accumulating per-byte frequency
    counts. The whole-file entropy is reported alongside a coalesced list
    of contiguous chunks whose individual entropy exceeded
    ``HIGH_ENTROPY_THRESHOLD`` (7.5 bits/byte) — a strong signal that the
    region is encrypted, compressed, or otherwise high-entropy. No raw
    byte arrays are returned, keeping the LLM context window protected.

    Args:
        file_path: Absolute or expanded path to the binary on disk. This
            should be the ``file_path`` field returned by the JTAG
            cartridge's ``dump_firmware`` tool (or any other producer that
            registers blobs with :class:`~wintermute.utils.blob_manager.WorkspaceManager`).
        block_size: Size in bytes of each chunk used for the per-region
            entropy calculation. Defaults to 256.

    Returns:
        A dictionary serialised from :class:`EntropyAnalysisResult` with
        the keys:

            * ``file_path``: Resolved path of the inspected file.
            * ``file_size_bytes``: Total bytes processed.
            * ``block_size``: The chunk size used.
            * ``overall_entropy``: Shannon entropy across the whole file
              (0.0–8.0 bits/byte).
            * ``is_likely_encrypted_or_compressed``: ``True`` when
              ``overall_entropy`` exceeds 7.5.
            * ``high_entropy_blocks``: List of
              ``{start_offset, end_offset}`` (hex strings) describing
              coalesced runs of high-entropy chunks.
            * ``high_entropy_block_count``: Number of entries in the list.

    Raises:
        ValueError: If ``block_size`` is less than 1.
        FileNotFoundError: If ``file_path`` does not point to a real file.
    """
    if block_size < 1:
        raise ValueError("block_size must be >= 1")
    path = _ensure_file(file_path)

    overall_counts: Counter[int] = Counter()
    overall_total = 0

    coalesced: List[EntropyBlock] = []
    pending_start: int | None = None
    pending_end = 0

    offset = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(block_size)
            if not chunk:
                break
            chunk_counts = Counter(chunk)
            block_entropy = _shannon_entropy(chunk_counts, len(chunk))
            overall_counts.update(chunk_counts)
            overall_total += len(chunk)

            if block_entropy > HIGH_ENTROPY_THRESHOLD:
                if pending_start is None:
                    pending_start = offset
                pending_end = offset + len(chunk)
            elif pending_start is not None:
                coalesced.append(
                    EntropyBlock(
                        start_offset=hex(pending_start),
                        end_offset=hex(pending_end),
                    )
                )
                pending_start = None
            offset += len(chunk)

    if pending_start is not None:
        coalesced.append(
            EntropyBlock(
                start_offset=hex(pending_start),
                end_offset=hex(pending_end),
            )
        )

    overall_entropy = _shannon_entropy(overall_counts, overall_total)
    result = EntropyAnalysisResult(
        file_path=str(path),
        file_size_bytes=overall_total,
        block_size=block_size,
        overall_entropy=round(overall_entropy, 6),
        is_likely_encrypted_or_compressed=overall_entropy > HIGH_ENTROPY_THRESHOLD,
        high_entropy_blocks=coalesced,
        high_entropy_block_count=len(coalesced),
    )
    return result.model_dump()


def scan_for_secrets(file_path: str) -> dict[str, Any]:
    """Hunt for cryptographic constants, key blobs, and backdoor markers.

    Streams the file through a small set of byte-pattern detectors (well-
    known S-boxes and hash IVs) and regex-based text detectors (PEM
    headers, SSH public-key prefixes, AWS access keys, hardcoded shell
    paths, common backdoor keywords). Each detector reports the absolute
    file offset where its pattern was located. To keep the LLM-bound
    payload compact, no surrounding bytes are returned and a per-type cap
    of 64 offsets is enforced.

    Args:
        file_path: Absolute or expanded path to the binary on disk. Pass
            the ``file_path`` produced by ``dump_firmware`` so the analysis
            stays inside the workspace boundary.

    Returns:
        A dictionary serialised from :class:`SecretScanResult` with the
        keys:

            * ``file_path``: Resolved path of the inspected file.
            * ``file_size_bytes``: Total bytes scanned.
            * ``matches``: ``{detector_name: [hex_offset, ...]}`` mapping.
              Detectors that fire zero times are omitted.
            * ``total_matches``: Sum of offsets across all detectors.
            * ``truncated``: ``True`` if at least one detector hit the
              per-type offset cap.

    Raises:
        FileNotFoundError: If ``file_path`` does not point to a real file.
    """
    path = _ensure_file(file_path)
    file_size = path.stat().st_size

    matches: dict[str, list[int]] = {}
    truncated = False

    def record(name: str, abs_offset: int) -> None:
        nonlocal truncated
        bucket = matches.setdefault(name, [])
        if bucket and bucket[-1] == abs_offset:
            return
        if len(bucket) >= _MAX_OFFSETS_PER_TYPE:
            truncated = True
            return
        bucket.append(abs_offset)

    chunk_offset = 0
    prev_iter_end = 0
    prev_tail = b""

    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_STREAM_CHUNK_SIZE)
            if not chunk:
                break
            buffer = prev_tail + chunk
            buffer_start = chunk_offset - len(prev_tail)
            new_iter_end = chunk_offset + len(chunk)

            for name, pattern_bytes in _BYTE_PATTERNS:
                pattern_len = len(pattern_bytes)
                start = 0
                while True:
                    idx = buffer.find(pattern_bytes, start)
                    if idx < 0:
                        break
                    abs_offset = buffer_start + idx
                    if abs_offset + pattern_len > prev_iter_end:
                        record(name, abs_offset)
                    start = idx + 1

            for name, pattern in _TEXT_PATTERNS:
                for hit in pattern.finditer(buffer):
                    abs_offset = buffer_start + hit.start()
                    abs_end = buffer_start + hit.end()
                    if abs_end > prev_iter_end:
                        record(name, abs_offset)

            prev_iter_end = new_iter_end
            prev_tail = (
                buffer[-_SECRET_OVERLAP:] if len(buffer) > _SECRET_OVERLAP else buffer
            )
            chunk_offset = new_iter_end

    hex_matches = {
        name: [hex(off) for off in offsets] for name, offsets in sorted(matches.items())
    }
    total = sum(len(offsets) for offsets in matches.values())

    result = SecretScanResult(
        file_path=str(path),
        file_size_bytes=file_size,
        matches=hex_matches,
        total_matches=total,
        truncated=truncated,
    )
    return result.model_dump()


def extract_strings(file_path: str, min_length: int = 8) -> dict[str, Any]:
    """Pull printable ASCII strings out of a binary and surface the most
    interesting ones.

    Scans the file for runs of printable ASCII (``0x20``–``0x7e``) of at
    least ``min_length`` bytes. Rather than returning every match — which
    would flood the LLM context on a real firmware image — only summary
    counts and a top-20 list of strings containing security-relevant
    keywords (``http``, ``admin``, ``root``, ``password``, ``%s``,
    ``/bin/sh``) are returned.

    The file is read into memory once. For typical firmware images
    (under a few hundred MB) this is comfortably faster than streaming
    decode; very large blobs should be sharded by the caller.

    Args:
        file_path: Absolute or expanded path to the binary on disk. Pass
            the ``file_path`` field from a ``dump_firmware`` descriptor
            so the analysis stays inside the workspace boundary.
        min_length: Minimum length in bytes for a run to qualify as a
            string. Must be >= 1. Defaults to 8.

    Returns:
        A dictionary serialised from :class:`StringExtractionResult` with
        the keys:

            * ``file_path``: Resolved path of the inspected file.
            * ``file_size_bytes``: Total bytes scanned.
            * ``min_length``: Minimum string length applied.
            * ``total_strings_found``: Total qualifying runs (including
              duplicates).
            * ``unique_strings``: Cardinality of the deduplicated set.
            * ``top_20_interesting_strings``: Up to 20 strings ranked by
              keyword hits and length.

    Raises:
        ValueError: If ``min_length`` is less than 1.
        FileNotFoundError: If ``file_path`` does not point to a real file.
    """
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    path = _ensure_file(file_path)
    data = path.read_bytes()

    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)

    total = 0
    unique: set[str] = set()
    scored: dict[str, int] = {}

    for match in pattern.finditer(data):
        try:
            value = match.group().decode("ascii")
        except UnicodeDecodeError:
            continue
        total += 1
        unique.add(value)
        if value in scored:
            continue
        score = _interest_score(value)
        if score > 0:
            scored[value] = score

    ranked = sorted(
        scored.items(),
        key=lambda kv: (-kv[1], -len(kv[0]), kv[0]),
    )
    top = [value for value, _score in ranked[:_TOP_INTERESTING_STRINGS]]

    result = StringExtractionResult(
        file_path=str(path),
        file_size_bytes=len(data),
        min_length=min_length,
        total_strings_found=total,
        unique_strings=len(unique),
        top_20_interesting_strings=top,
    )
    return result.model_dump()


# ---------------------------------------------------------------------------
# Cartridge wrapper
# ---------------------------------------------------------------------------


class FirmwareAnalysisCartridge:
    """Stateless bundle of firmware analysis tools.

    The cartridge exists primarily so the framework can register each
    method through :func:`wintermute.ai.utils.tool_factory.function_to_tool`
    in one shot. Every method delegates to the corresponding module-level
    function and is designed to consume the ``file_path`` field returned
    by ``JTAGCartridge.dump_firmware``.
    """

    def analyze_entropy(self, file_path: str, block_size: int = 256) -> dict[str, Any]:
        """Delegate to :func:`analyze_entropy`."""
        return analyze_entropy(file_path, block_size)

    def scan_for_secrets(self, file_path: str) -> dict[str, Any]:
        """Delegate to :func:`scan_for_secrets`."""
        return scan_for_secrets(file_path)

    def extract_strings(self, file_path: str, min_length: int = 8) -> dict[str, Any]:
        """Delegate to :func:`extract_strings`."""
        return extract_strings(file_path, min_length)

    def find_base_address(
        self,
        file_path: str,
        arch: str = "",
        min_addr: int = 0x0,
        max_addr: int = 0xFFFFFFFF,
    ) -> dict[str, Any]:
        """Locate the most likely memory load address of a raw firmware blob.

        Runs the ``basefind`` heuristic scanner over the binary at
        ``file_path``: every candidate base in ``[min_addr, max_addr)`` is
        scored by counting how many pointer values inside the image, when
        rebased to that candidate, fall on the start of a printable string
        already found in the same image (and, when ``arch`` is supplied,
        on a known function prologue).

        This is a **heavy multiprocessing scan** — for a 32-bit address
        space it materialises ~1M candidates per page-size step. To keep
        the host responsive the wrapper caps worker processes at half of
        ``os.cpu_count()`` and turns off the library's verbose / progress
        chatter. The full scoring array (potentially tens of thousands of
        entries) is **never** returned to the LLM; only the top 5
        candidates and a small metadata block are surfaced.

        Args:
            file_path: Absolute or expanded path to the raw firmware
                binary. Pass the ``file_path`` from a ``dump_firmware``
                descriptor so the analysis stays inside the workspace
                boundary registered by
                :class:`~wintermute.utils.blob_manager.WorkspaceManager`.
            arch: Optional CPU architecture for prologue heuristic
                scoring (one of ``"arm"``, ``"thumb"``, ``"mips"``,
                ``"x86"``). An empty string disables prologue scoring.
            min_addr: Inclusive lower bound of the address range to
                search. Defaults to ``0x0``.
            max_addr: Exclusive upper bound of the address range to
                search. Defaults to ``0xFFFFFFFF``.

        Returns:
            A dictionary serialised from :class:`BaseAddressAnalysisResult`
            with the keys:

                * ``file_path``: Resolved path of the inspected file.
                * ``file_size_bytes``: Size of the firmware blob.
                * ``scan_range``: ``{"min_addr": "0x...", "max_addr": "0x..."}``
                  echoed back as hex strings.
                * ``top_5_candidates``: Mapping of hex-formatted base
                  address to integer score, ordered highest-first.
                * ``candidates_considered``: Total non-zero scoring
                  candidates produced before truncation to the top 5.
                * ``metadata``: Inferred / configured fields (endianness,
                  pointer width, architecture).

        Raises:
            FileNotFoundError: If ``file_path`` does not point to a real
                file.
            ValueError: If ``min_addr`` >= ``max_addr`` or ``arch`` is not
                one of the supported architectures.
        """
        path = _ensure_file(file_path)
        file_size = path.stat().st_size

        cpu_count = os.cpu_count() or 1
        workers = max(1, cpu_count // 2)

        cfg = ScanConfig(
            min_addr=min_addr,
            max_addr=max_addr,
            workers=workers,
            verbose=False,
            progress=False,
            entropy_check=False,
            arch=arch or None,
        )

        finder = FWBasefind(str(path), config=cfg)
        raw_scores = finder.run()

        ranked = sorted(raw_scores, key=lambda pair: pair[1], reverse=True)
        top: dict[str, int] = {}
        for base, score in ranked[:_TOP_BASE_CANDIDATES]:
            top[f"0x{base:08x}"] = int(score)

        result = BaseAddressAnalysisResult(
            file_path=str(path),
            file_size_bytes=file_size,
            scan_range={
                "min_addr": f"0x{min_addr:08x}",
                "max_addr": f"0x{max_addr:08x}",
            },
            top_5_candidates=top,
            candidates_considered=len(raw_scores),
            metadata={
                "endian": cfg.endian,
                "bits": str(cfg.bits),
                "arch": cfg.arch or "",
                "workers": str(cfg.workers),
            },
        )
        return result.model_dump()


__all__ = [
    "BaseAddressAnalysisResult",
    "EntropyAnalysisResult",
    "EntropyBlock",
    "FirmwareAnalysisCartridge",
    "HIGH_ENTROPY_THRESHOLD",
    "INTERESTING_STRING_KEYWORDS",
    "SecretScanResult",
    "StringExtractionResult",
    "analyze_entropy",
    "extract_strings",
    "scan_for_secrets",
]
