"""
basefind
~~~~~~~~
Heuristic firmware base-address finder.

Import the main class directly::

    from basefind import FWBasefind

    finder = FWBasefind("firmware.bin", min_addr=0x80000000)
    results = finder.run()
    finder.print_results()
"""

from ._core import KNOWN_HEADERS, PROLOGUE_PATTERNS, FWBasefind, ScanConfig

__all__ = ["FWBasefind", "ScanConfig", "KNOWN_HEADERS", "PROLOGUE_PATTERNS"]
__version__ = "3.0.0"
