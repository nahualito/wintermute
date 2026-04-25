"""
basefind._core
~~~~~~~~~~~~~~
FWBasefind class — heuristic firmware base-address finder.

All 11 capabilities from implementation.md are implemented here:
  1.  Big-endian pointer support
  2.  64-bit pointer support
  3.  Non-aligned pointer scanning
  4.  Progress indicator with ETA
  5.  Two-pass refinement
  6.  Entropy / compression detection
  7.  UTF-16LE string detection
  8.  Architecture prologue heuristic scoring
  9.  JSON / CSV output
  10. Firmware header skip / auto-detection
  11. Multiprocessing
"""

from __future__ import annotations

import csv
import gc
import io
import json
import math
import multiprocessing
import os
import re
import signal
import struct
import sys
import time
from dataclasses import dataclass, field
from operator import itemgetter
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ._worker import score_chunk

# ---------------------------------------------------------------------------
# Internal scoring context (groups tables to reduce argument counts)
# ---------------------------------------------------------------------------


@dataclass
class _ScoringCtx:
    """Immutable scoring context passed between internal methods."""

    str_table: StrTable
    ptr_table: PtrTable
    prologue_table: StrTable
    image_size: int


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------
ScoreList = List[Tuple[int, int]]
PtrTable = Dict[int, int]
StrTable = Set[int]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Printable ASCII character class used for string detection.
_CHARS: str = r"A-Za-z0-9/\-:.,_$%'\"()[\]<> "

#: Known firmware header magic bytes -> (description, bytes_to_skip).
#: skip=0 means "warn but do not skip" (compressed / filesystem images).
KNOWN_HEADERS: Dict[bytes, Tuple[str, int]] = {
    b"\x27\x05\x19\x56": ("U-Boot uImage", 64),
    b"\x48\x44\x52\x30": ("TRX header", 28),
    b"\x2e\x73\x71\x73": ("SquashFS filesystem", 0),
    b"\x1f\x8b\x08": ("gzip stream", 0),
    b"\xfd\x37\x7a\x58": ("XZ stream", 0),
    b"\x5d\x00\x00": ("LZMA stream", 0),
}

#: Known function prologue byte patterns per architecture.
PROLOGUE_PATTERNS: Dict[str, List[bytes]] = {
    "arm": [b"\x00\x48\x2d\xe9", b"\xf0\x4f\x2d\xe9"],
    "thumb": [b"\x10\xb5", b"\x30\xb5", b"\x70\xb5", b"\xf0\xb5"],
    "mips": [b"\x27\xbd", b"\xff\xbd"],
    "x86": [b"\x55\x89\xe5", b"\x55\x48\x89\xe5"],
}

_VALID_ENDIAN: FrozenSet[str] = frozenset({"little", "big"})
_VALID_BITS: FrozenSet[int] = frozenset({32, 64})
_VALID_ALIGN: FrozenSet[int] = frozenset({1, 2, 4})
_VALID_ARCH: FrozenSet[str] = frozenset(PROLOGUE_PATTERNS.keys())
_VALID_FMT: FrozenSet[str] = frozenset({"json", "csv"})


# ---------------------------------------------------------------------------
# ScanConfig — groups all tunable parameters to keep FWBasefind lean
# ---------------------------------------------------------------------------


@dataclass  # pylint: disable=too-many-instance-attributes
class ScanConfig:  # pylint: disable=too-many-instance-attributes
    """All tunable parameters for a firmware base-address scan.

    Grouping parameters here keeps ``FWBasefind.__init__`` within pylint's
    attribute and argument limits while preserving the full public API.

    Parameters
    ----------
    min_addr:
        Start of the base-address search range (inclusive).
    max_addr:
        End of the base-address search range (exclusive).
    page_size:
        Step between candidate base addresses.
    min_length:
        Minimum printable-string length to record.
    verbose:
        Print informational messages to stdout.
    endian:
        Pointer byte order: ``"little"`` or ``"big"``.
    bits:
        Pointer width: ``32`` or ``64``.
    ptr_align:
        Pointer scan alignment: ``1``, ``2``, or ``4`` bytes.
    progress:
        Show a progress / ETA line during the scoring loop.
    refine:
        Run a fine-grained second pass around the top candidates.
    refine_window:
        Address window (bytes) around each coarse candidate for refinement.
    refine_top_n:
        Number of top coarse candidates to refine.
    entropy_check:
        Compute Shannon entropy before scanning and warn if suspicious.
    wide_strings:
        Also scan for UTF-16LE (wide) strings.
    arch:
        Architecture for prologue heuristic scoring, or ``None``.
    output_file:
        If set, save results to this path after scanning.
    output_format:
        Format for *output_file*: ``"json"`` or ``"csv"``.
    skip_bytes:
        Manually skip this many bytes at the start of the file.
    auto_header:
        Attempt to auto-detect and skip known vendor headers.
    workers:
        Number of parallel worker processes (``0`` = auto).
    """

    min_addr: int = 0x00000000
    max_addr: int = 0xF0000000
    page_size: int = 0x1000
    min_length: int = 10
    verbose: bool = True
    endian: str = "little"
    bits: int = 32
    ptr_align: int = 4
    progress: bool = True
    refine: bool = False
    refine_window: int = 0x1000
    refine_top_n: int = 5
    entropy_check: bool = True
    wide_strings: bool = False
    arch: Optional[str] = None
    output_file: Optional[str] = None
    output_format: str = "json"
    skip_bytes: int = 0
    auto_header: bool = True
    workers: int = 1
    scores: ScoreList = field(default_factory=list)

    def validate(self) -> None:
        """Raise ``ValueError`` for any invalid parameter combination."""
        if self.endian not in _VALID_ENDIAN:
            raise ValueError(f"endian must be one of {_VALID_ENDIAN}")
        if self.bits not in _VALID_BITS:
            raise ValueError(f"bits must be one of {_VALID_BITS}")
        if self.ptr_align not in _VALID_ALIGN:
            raise ValueError(f"ptr_align must be one of {_VALID_ALIGN}")
        if self.arch is not None and self.arch not in _VALID_ARCH:
            raise ValueError(f"arch must be one of {_VALID_ARCH} or None")
        if self.output_format not in _VALID_FMT:
            raise ValueError(f"output_format must be one of {_VALID_FMT}")
        if self.min_addr >= self.max_addr:
            raise ValueError("min_addr must be less than max_addr")
        if self.page_size < 1:
            raise ValueError("page_size must be >= 1")
        if self.min_length < 1:
            raise ValueError("min_length must be >= 1")


# ---------------------------------------------------------------------------
# FWBasefind
# ---------------------------------------------------------------------------


class FWBasefind:  # pylint: disable=too-many-public-methods
    """Heuristic firmware base-address finder.

    Scores candidate base addresses by counting how many pointer values in the
    binary, when rebased to a candidate address, land on the start of a
    printable string found within the same binary.  Optionally also scores
    against known function prologues for a given architecture.

    Parameters
    ----------
    filepath:
        Path to the raw firmware binary.
    config:
        Optional :class:`ScanConfig` instance.  When omitted a default config
        is created and all keyword arguments are forwarded to it.
    **kwargs:
        Forwarded to :class:`ScanConfig` when *config* is ``None``.

    Examples
    --------
    Library usage::

        from basefind import FWBasefind

        finder = FWBasefind("firmware.bin", min_addr=0x80000000, endian="little")
        results = finder.run()
        for base, score in results:
            print(f"0x{base:08x}  {score}")

    Standalone::

        python -m basefind firmware.bin --min_addr 0x80000000
    """

    def __init__(
        self,
        filepath: str,
        config: Optional[ScanConfig] = None,
        **kwargs: object,
    ) -> None:
        self.filepath: str = filepath
        self.cfg: ScanConfig = config if config is not None else ScanConfig(**kwargs)  # type: ignore[arg-type]
        self.cfg.validate()

        # Resolve worker count (0 -> cpu_count)
        if self.cfg.workers <= 0:
            self.cfg.workers = os.cpu_count() or 1

        # Derived pointer format (Caps 1 + 2)
        _endian_char = "<" if self.cfg.endian == "little" else ">"
        _type_char = "L" if self.cfg.bits == 32 else "Q"
        self._ptr_fmt: str = f"{_endian_char}{_type_char}"
        self._ptr_size: int = 4 if self.cfg.bits == 32 else 8

        # Compiled regex patterns for string scanning
        self._pattern: re.Pattern[str] = re.compile(
            f"[{_CHARS}]{{{self.cfg.min_length},}}"
        )
        self._patternc: re.Pattern[str] = re.compile(f"[{_CHARS}]{{1,}}")

    # ------------------------------------------------------------------
    # Convenience property so callers can still do finder.scores
    # ------------------------------------------------------------------

    @property
    def scores(self) -> ScoreList:
        """Live list of ``(base_address, score)`` tuples from the last run."""
        return self.cfg.scores

    @scores.setter
    def scores(self, value: ScoreList) -> None:
        self.cfg.scores = value

    # ------------------------------------------------------------------
    # Cap 6 — Entropy
    # ------------------------------------------------------------------

    def compute_entropy(self) -> float:
        """Compute Shannon entropy of the firmware file in bits per byte.

        Returns
        -------
        float
            Entropy value in the range [0.0, 8.0].
        """
        counts: List[int] = [0] * 256
        total: int = 0
        with open(self.filepath, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                for byte in chunk:
                    counts[byte] += 1
                    total += 1
        if total == 0:
            return 0.0
        entropy: float = 0.0
        for count in counts:
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)
        return entropy

    def _check_entropy(self) -> None:
        """Run entropy check and print warnings if thresholds are exceeded."""
        entropy = self.compute_entropy()
        if self.cfg.verbose:
            print(f"File entropy: {entropy:.4f} bits/byte")
        if entropy > 7.2:
            print(
                f"WARNING: High entropy ({entropy:.2f} bpb) — image may be "
                "compressed or encrypted. Results will likely be meaningless.\n"
                "Decompress or decrypt the image first, "
                "or pass --no-entropy-check to skip this warning."
            )
        elif entropy < 1.0:
            print(
                f"WARNING: Very low entropy ({entropy:.2f} bpb) — image may "
                "be mostly padding or flash fill."
            )

    # ------------------------------------------------------------------
    # Cap 10 — Header detection
    # ------------------------------------------------------------------

    def detect_header(self) -> Tuple[Optional[str], int]:
        """Detect a known vendor header at the start of the firmware file.

        Returns
        -------
        Tuple[Optional[str], int]
            ``(description, suggested_skip_bytes)``.
            Returns ``(None, 0)`` when no known header is found.
        """
        with open(self.filepath, "rb") as fh:
            magic = fh.read(16)
        for sig, (desc, skip) in KNOWN_HEADERS.items():
            if magic.startswith(sig):
                return desc, skip
        return None, 0

    def _resolve_skip(self) -> int:
        """Return the effective number of bytes to skip before scanning."""
        if self.cfg.skip_bytes > 0:
            return self.cfg.skip_bytes
        if self.cfg.auto_header:
            desc, suggested = self.detect_header()
            if desc is not None:
                if suggested > 0:
                    if self.cfg.verbose:
                        print(
                            f"Detected {desc} header — "
                            f"skipping first {suggested} bytes."
                        )
                    return suggested
                if self.cfg.verbose:
                    print(
                        f"WARNING: Detected {desc} — "
                        "image may not be scannable directly."
                    )
        return 0

    # ------------------------------------------------------------------
    # Cap 3 — Pointer extraction (non-aligned sliding window)
    # ------------------------------------------------------------------

    def get_pointers(self, raw: bytes, skip: int = 0) -> PtrTable:
        """Extract a pointer frequency table from raw firmware bytes.

        Parameters
        ----------
        raw:
            Full firmware image as bytes.
        skip:
            Number of bytes to skip at the start.

        Returns
        -------
        Dict[int, int]
            Mapping of ``{pointer_value: occurrence_count}``.
        """
        table: PtrTable = {}
        end = len(raw) - self._ptr_size + 1
        for i in range(skip, end, self.cfg.ptr_align):
            (value,) = struct.unpack_from(self._ptr_fmt, raw, i)
            table[value] = table.get(value, 0) + 1
        return table

    # ------------------------------------------------------------------
    # Cap 7 — String extraction (ASCII + optional UTF-16LE)
    # ------------------------------------------------------------------

    def get_strings(self, raw: bytes, skip: int = 0) -> StrTable:
        """Scan firmware bytes for printable ASCII string start offsets.

        Parameters
        ----------
        raw:
            Full firmware image as bytes.
        skip:
            Number of bytes to skip at the start.

        Returns
        -------
        Set[int]
            Offsets of string starts within *raw*.
        """
        table: StrTable = set()
        size = len(raw)
        offset = skip
        while offset < size:
            window = raw[offset : offset + 10].decode("latin-1")
            match = self._pattern.match(window)
            if match:
                if offset > 0:
                    prev = chr(raw[offset - 1])
                    if not self._patternc.match(prev):
                        table.add(offset)
                else:
                    table.add(offset)
                offset += len(match.group(0))
            else:
                offset += 1
        return table

    def get_wide_strings(self, raw: bytes, skip: int = 0) -> StrTable:
        """Scan firmware bytes for UTF-16LE string start offsets.

        Parameters
        ----------
        raw:
            Full firmware image as bytes.
        skip:
            Number of bytes to skip at the start.

        Returns
        -------
        Set[int]
            Offsets of wide-string starts within *raw*.
        """
        table: StrTable = set()
        printable: Set[int] = set(_CHARS.encode("latin-1"))
        size = len(raw)
        i = skip
        while i < size - 1:
            j = i
            while j + 1 < size and raw[j] in printable and raw[j + 1] == 0:
                j += 2
            run_len = (j - i) // 2
            if run_len >= self.cfg.min_length:
                if i < 2 or not (raw[i - 2] in printable and raw[i - 1] == 0):
                    table.add(i)
                i = j
            else:
                i += 1
        return table

    # ------------------------------------------------------------------
    # Cap 8 — Prologue heuristic
    # ------------------------------------------------------------------

    def get_prologues(self, raw: bytes) -> StrTable:
        """Return offsets of known function prologues for the configured arch.

        Parameters
        ----------
        raw:
            Full firmware image as bytes.

        Returns
        -------
        Set[int]
            Offsets where a known prologue pattern starts.
        """
        if self.cfg.arch is None:
            return set()
        patterns = PROLOGUE_PATTERNS.get(self.cfg.arch, [])
        offsets: StrTable = set()
        for pat in patterns:
            start = 0
            while True:
                idx = raw.find(pat, start)
                if idx == -1:
                    break
                offsets.add(idx)
                start = idx + 1
        return offsets

    # ------------------------------------------------------------------
    # Cap 9 — Output serialisation
    # ------------------------------------------------------------------

    def to_json(self, n: int = 20) -> str:
        """Serialise top *n* results to a JSON string."""
        results = [
            {
                "base_address": f"0x{base:08x}",
                "base_address_int": base,
                "score": score,
            }
            for base, score in self.top_results(n)
        ]
        payload = {"firmware": self.filepath, "results": results}
        return json.dumps(payload, indent=2)

    def to_csv(self, n: int = 20) -> str:
        """Serialise top *n* results to a CSV string."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["base_address", "base_address_int", "score"])
        for base, score in self.top_results(n):
            writer.writerow([f"0x{base:08x}", base, score])
        return buf.getvalue()

    def save_results(self, path: str, fmt: str = "json", n: int = 20) -> None:
        """Write results to *path* in the specified format."""
        if fmt not in _VALID_FMT:
            raise ValueError(f"fmt must be one of {_VALID_FMT}")
        content = self.to_json(n) if fmt == "json" else self.to_csv(n)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if self.cfg.verbose:
            print(f"Results saved to {path}")

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def top_results(self, n: int = 20) -> ScoreList:
        """Return the top *n* ``(base_address, score)`` tuples by score."""
        return sorted(self.cfg.scores, key=itemgetter(1), reverse=True)[:n]

    def print_results(self, n: int = 20) -> None:
        """Print the top *n* candidate base addresses to stdout."""
        print(f"\nTop {n} base address candidates:")
        for base, score in self.top_results(n):
            print(f"  0x{base:08x}  score: {score}")

    # ------------------------------------------------------------------
    # Cap 5 — Two-pass refinement
    # ------------------------------------------------------------------

    def _refine(
        self,
        str_table: StrTable,
        ptr_table_snapshot: PtrTable,
        image_size: int,
    ) -> None:
        """Fine-grained second pass around the top coarse candidates."""
        fine_step = self._ptr_size
        fine_scores: ScoreList = []

        for coarse_base, _ in self.top_results(self.cfg.refine_top_n):
            fine_scores.extend(
                self._refine_window(
                    coarse_base,
                    str_table,
                    ptr_table_snapshot,
                    image_size,
                    fine_step,
                )
            )

        merged: Dict[int, int] = dict(self.cfg.scores)
        for base, score in fine_scores:
            if base not in merged or score > merged[base]:
                merged[base] = score
        self.cfg.scores = list(merged.items())

    def _refine_window(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        coarse_base: int,
        str_table: StrTable,
        ptr_table_snapshot: PtrTable,
        image_size: int,
        fine_step: int,
    ) -> ScoreList:
        """Score a single refinement window around *coarse_base*."""
        window_start = max(self.cfg.min_addr, coarse_base - self.cfg.refine_window)
        window_end = min(
            self.cfg.max_addr,
            coarse_base + self.cfg.refine_window + fine_step,
        )
        bases = list(range(window_start, window_end, fine_step))
        # Reuse the worker function to avoid code duplication
        return score_chunk((bases, dict(ptr_table_snapshot), str_table, image_size))

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    def run(self) -> ScoreList:
        """Execute the full firmware base-address scan.

        Returns
        -------
        List[Tuple[int, int]]
            Top 20 ``(base_address, score)`` tuples sorted by score descending.
        """
        if self.cfg.entropy_check:
            self._check_entropy()

        effective_skip = self._resolve_skip()
        raw, image_size = self._load_image(effective_skip)
        str_table, ptr_table, prologue_table = self._build_tables(raw, effective_skip)
        ptr_table_snapshot: PtrTable = dict(ptr_table)

        ctx = _ScoringCtx(
            str_table=str_table,
            ptr_table=ptr_table,
            prologue_table=prologue_table,
            image_size=image_size,
        )

        self.cfg.scores = []
        gc.disable()
        self._register_sigint()

        if self.cfg.workers > 1:
            self._run_parallel(ctx)
        else:
            self._run_serial(ctx)

        gc.enable()

        if self.cfg.refine:
            if self.cfg.verbose:
                print("Running refinement pass...")
            self._refine(str_table, ptr_table_snapshot, image_size)

        if self.cfg.output_file:
            self.save_results(self.cfg.output_file, fmt=self.cfg.output_format)

        return self.top_results()

    def _load_image(self, effective_skip: int) -> Tuple[bytes, int]:
        """Read the firmware file into memory and return (raw, image_size)."""
        image_size_full = os.path.getsize(self.filepath)
        with open(self.filepath, "rb") as fh:
            raw: bytes = fh.read()
        return raw, image_size_full - effective_skip

    def _build_tables(
        self, raw: bytes, skip: int
    ) -> Tuple[StrTable, PtrTable, StrTable]:
        """Build string, pointer, and prologue tables from *raw*."""
        if self.cfg.verbose:
            print("Scanning binary for strings...")
        str_table: StrTable = self.get_strings(raw, skip=skip)
        if self.cfg.wide_strings:
            wide = self.get_wide_strings(raw, skip=skip)
            if self.cfg.verbose:
                print(f"Total wide strings found: {len(wide)}")
            str_table |= wide
        if self.cfg.verbose:
            print(f"Total strings found: {len(str_table)}")

        if self.cfg.verbose:
            print("Scanning binary for pointers...")
        ptr_table: PtrTable = self.get_pointers(raw, skip=skip)
        if self.cfg.verbose:
            print(f"Total pointers found: {len(ptr_table)}")

        prologue_table: StrTable = set()
        if self.cfg.arch is not None:
            prologue_table = self.get_prologues(raw)
            if self.cfg.verbose:
                print(f"Total prologue hits found: {len(prologue_table)}")

        return str_table, ptr_table, prologue_table

    def _register_sigint(self) -> None:
        """Register a SIGINT handler that prints partial results on Ctrl+C."""

        def _handler(signum: int, frame: object) -> None:
            del signum, frame  # unused but required by signal protocol
            print()
            self.print_results()
            sys.exit(0)

        signal.signal(signal.SIGINT, _handler)

    # ------------------------------------------------------------------
    # Internal: serial scoring loop (Cap 4 progress)
    # ------------------------------------------------------------------

    def _run_serial(self, ctx: _ScoringCtx) -> None:
        """Single-threaded scoring loop with optional progress display."""
        total_steps = max(
            1, (self.cfg.max_addr - self.cfg.min_addr) // self.cfg.page_size
        )
        step_num: int = 0
        start_time: float = time.monotonic()
        top_score: int = 0
        ptr_table = ctx.ptr_table

        for base in range(self.cfg.min_addr, self.cfg.max_addr, self.cfg.page_size):
            self._maybe_print_progress(
                base, step_num, total_steps, start_time, top_score
            )

            to_delete = [p for p in ptr_table if p < base]
            for p in to_delete:
                del ptr_table[p]

            score = self._score_base(base, ctx)

            if score:
                self.cfg.scores.append((base, score))
                if score > top_score:
                    top_score = score
                    if self.cfg.verbose:
                        if self.cfg.progress:
                            print()
                        print(f"New highest score, 0x{base:08x}: {score}")

            step_num += 1

        if self.cfg.verbose and self.cfg.progress:
            print()

    def _score_base(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, base: int, ctx: _ScoringCtx
    ) -> int:
        """Compute the score for a single candidate base address."""
        score: int = 0
        for ptr, count in ctx.ptr_table.items():
            if ptr >= base + ctx.image_size:
                continue
            offset = ptr - base
            if offset in ctx.str_table:
                score += count
            if ctx.prologue_table and offset in ctx.prologue_table:
                score += count
        return score

    def _maybe_print_progress(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        base: int,
        step_num: int,
        total_steps: int,
        start_time: float,
        top_score: int,
    ) -> None:
        """Print a progress line every 256 steps if enabled."""
        if not (
            self.cfg.verbose
            and self.cfg.progress
            and step_num % 256 == 0
            and step_num > 0
        ):
            return
        elapsed = time.monotonic() - start_time
        rate = step_num / elapsed if elapsed > 0 else 1.0
        remaining = (total_steps - step_num) / rate
        pct = 100.0 * step_num / total_steps
        print(
            f"\r  [{pct:5.1f}%] base=0x{base:08x}  "
            f"elapsed={elapsed:.0f}s  eta={remaining:.0f}s  "
            f"top={top_score}",
            end="",
            flush=True,
        )

    # ------------------------------------------------------------------
    # Internal: parallel scoring loop (Cap 11)
    # ------------------------------------------------------------------

    def _run_parallel(self, ctx: _ScoringCtx) -> None:
        """Distribute the scoring loop across worker processes."""
        combined_table: StrTable = ctx.str_table | ctx.prologue_table
        all_bases: List[int] = list(
            range(self.cfg.min_addr, self.cfg.max_addr, self.cfg.page_size)
        )
        chunk_size = max(1, len(all_bases) // self.cfg.workers)
        chunks = [
            all_bases[i : i + chunk_size] for i in range(0, len(all_bases), chunk_size)
        ]
        work_args = [
            (chunk, dict(ctx.ptr_table), combined_table, ctx.image_size)
            for chunk in chunks
        ]

        if self.cfg.verbose:
            print(
                f"Scanning with {self.cfg.workers} workers "
                f"({len(all_bases)} base addresses)..."
            )

        with multiprocessing.Pool(processes=self.cfg.workers) as pool:
            chunk_results = pool.map(score_chunk, work_args)

        for chunk in chunk_results:
            self.cfg.scores.extend(chunk)
