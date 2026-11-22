"""Frozen research Core V2.3. Load with the portable loader."""
from pathlib import Path
import sys
_DIRECTORY = str(Path(__file__).resolve().parent)
if _DIRECTORY not in sys.path:
    sys.path.insert(0, _DIRECTORY)
from .core_v2_3 import Core,VERSION,CONFIG
