import logging
import os
import sys

from . import core, peripherals

# Get current directory
parent_dir = os.path.abspath(os.path.dirname(__file__))

# Construct the path for the vendor directory
vendor_dir = os.path.join(parent_dir, "vendor")

# Add the vendor directory into Python's module search path
sys.path.append(vendor_dir)

# For adding logging capabilities to the package with user control
logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"

__all__ = ["core", "peripherals", "WintermuteREPL", "basemodels"]
