"""
basefind.__main__
~~~~~~~~~~~~~~~~~
Standalone CLI entry point.

Run as::

    python -m basefind firmware.bin [options]
"""

from __future__ import annotations

import argparse
import os
import sys

from ._core import FWBasefind, ScanConfig


def _auto_int(value: str) -> int:
    """Parse an integer literal in any base (hex, octal, decimal)."""
    return int(value, 0)


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="basefind",
        description=(
            "Heuristic firmware base-address finder.\n\n"
            "Scores candidate load addresses by counting how many pointer "
            "values in the binary land on string (or prologue) offsets when "
            "the image is rebased to that address."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Positional
    parser.add_argument("infile", help="raw firmware binary to scan")

    # Search range
    search = parser.add_argument_group("search range")
    search.add_argument(
        "--min_addr",
        type=_auto_int,
        default=0x0,
        metavar="ADDR",
        help="start searching at this address (default: 0x0)",
    )
    search.add_argument(
        "--max_addr",
        type=_auto_int,
        default=0xF0000000,
        metavar="ADDR",
        help="stop searching at this address (default: 0xf0000000)",
    )
    search.add_argument(
        "--page_size",
        type=_auto_int,
        default=0x1000,
        metavar="N",
        help="step between candidate base addresses (default: 0x1000)",
    )
    search.add_argument(
        "--min_length",
        type=int,
        default=10,
        metavar="N",
        help="minimum printable-string length (default: 10)",
    )

    # Pointer options (Caps 1, 2, 3)
    ptrs = parser.add_argument_group("pointer options")
    ptrs.add_argument(
        "--endian",
        choices=["little", "big"],
        default="little",
        help="pointer byte order (default: little)",
    )
    ptrs.add_argument(
        "--bits",
        type=int,
        choices=[32, 64],
        default=32,
        help="pointer width in bits (default: 32)",
    )
    ptrs.add_argument(
        "--ptr_align",
        type=int,
        choices=[1, 2, 4],
        default=4,
        metavar="{1,2,4}",
        help="pointer scan alignment in bytes (default: 4)",
    )

    # String options (Cap 7)
    strings = parser.add_argument_group("string options")
    strings.add_argument(
        "--wide-strings",
        action="store_true",
        help="also scan for UTF-16LE (wide) strings",
    )

    # Architecture / prologue (Cap 8)
    arch = parser.add_argument_group("architecture heuristic")
    arch.add_argument(
        "--arch",
        choices=["arm", "thumb", "mips", "x86"],
        default=None,
        help="enable function-prologue scoring for this architecture",
    )

    # Pre-scan checks (Caps 6, 10)
    prescan = parser.add_argument_group("pre-scan checks")
    prescan.add_argument(
        "--no-entropy-check",
        action="store_true",
        help="skip Shannon entropy pre-check",
    )
    prescan.add_argument(
        "--skip",
        type=_auto_int,
        default=0,
        metavar="N",
        help="manually skip first N bytes of the file",
    )
    prescan.add_argument(
        "--no-auto-header",
        action="store_true",
        help="disable automatic vendor-header detection",
    )

    # Refinement (Cap 5)
    refine = parser.add_argument_group("refinement")
    refine.add_argument(
        "--refine",
        action="store_true",
        help="run a fine-grained second pass around top candidates",
    )
    refine.add_argument(
        "--refine_window",
        type=_auto_int,
        default=0x1000,
        metavar="N",
        help="address window for refinement pass (default: 0x1000)",
    )
    refine.add_argument(
        "--refine_top_n",
        type=int,
        default=5,
        metavar="N",
        help="number of top candidates to refine (default: 5)",
    )

    # Output (Cap 9)
    output = parser.add_argument_group("output")
    output.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="save results to this file",
    )
    output.add_argument(
        "--output-format",
        choices=["json", "csv"],
        default="json",
        help="output file format (default: json)",
    )

    # Performance (Caps 4, 11)
    perf = parser.add_argument_group("performance")
    perf.add_argument(
        "--no-progress",
        action="store_true",
        help="disable the progress / ETA line",
    )
    perf.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help=(
            "parallel worker processes (default: 1). Use 0 to auto-detect CPU count."
        ),
    )

    # General
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress all informational output (implies --no-progress)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Parameters
    ----------
    argv:
        Argument list (defaults to ``sys.argv[1:]``).

    Returns
    -------
    int
        Exit code (0 = success, 1 = error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.isfile(args.infile):
        print(f"error: file not found: {args.infile}", file=sys.stderr)
        return 1

    effective_workers = os.cpu_count() or 1 if args.workers == 0 else args.workers

    cfg = ScanConfig(
        min_addr=args.min_addr,
        max_addr=args.max_addr,
        page_size=args.page_size,
        min_length=args.min_length,
        verbose=not args.quiet,
        endian=args.endian,
        bits=args.bits,
        ptr_align=args.ptr_align,
        progress=not (args.no_progress or args.quiet),
        refine=args.refine,
        refine_window=args.refine_window,
        refine_top_n=args.refine_top_n,
        entropy_check=not args.no_entropy_check,
        wide_strings=args.wide_strings,
        arch=args.arch,
        output_file=args.output,
        output_format=args.output_format,
        skip_bytes=args.skip,
        auto_header=not args.no_auto_header,
        workers=effective_workers,
    )

    finder = FWBasefind(filepath=args.infile, config=cfg)

    finder.run()
    finder.print_results()
    return 0


if __name__ == "__main__":
    sys.exit(main())
