"""
basefind._worker
~~~~~~~~~~~~~~~~
Module-level multiprocessing worker function.

Must live at module scope (not inside a class) so it is picklable
on all platforms, including macOS where the default start method is 'spawn'.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple


def score_chunk(
    args: Tuple[
        List[int],
        Dict[int, int],
        Set[int],
        int,
    ],
) -> List[Tuple[int, int]]:
    """Score a chunk of candidate base addresses.

    Parameters
    ----------
    args:
        Tuple of (bases, ptr_table, str_table, image_size).
        - bases      : ordered list of candidate base addresses to evaluate.
        - ptr_table  : {pointer_value: frequency} mapping (read-only).
        - str_table  : set of string-start offsets within the image.
        - image_size : byte length of the firmware image.

    Returns
    -------
    List of (base_address, score) tuples where score > 0, in base order.
    """
    bases, ptr_table, str_table, image_size = args
    results: List[Tuple[int, int]] = []

    # Sort once; allows early-exit when pointer exceeds window.
    ptr_items: List[Tuple[int, int]] = sorted(ptr_table.items())
    ptr_idx: int = 0
    total_ptrs: int = len(ptr_items)

    for base in bases:
        # Advance past pointers that are below this base — they can never
        # point into the image regardless of future base values in this chunk
        # because bases are monotonically increasing.
        while ptr_idx < total_ptrs and ptr_items[ptr_idx][0] < base:
            ptr_idx += 1

        score: int = 0
        for ptr, count in ptr_items[ptr_idx:]:
            if ptr >= base + image_size:
                break
            offset = ptr - base
            if offset in str_table:
                score += count

        if score:
            results.append((base, score))

    return results
