"""Non-authorizing dependency and source-pin check."""
import hashlib
from pathlib import Path
from research.resonance_core_v23 import VERSION,CONFIG
folder=Path(__file__).resolve().parent
pin="10790b3fb770496e8213986a320b825fd90dbc9990c96df81fa809fdd5ff257f"
assert hashlib.sha256((folder/"core_v2_3.py").read_bytes()).hexdigest()==pin
assert VERSION=="resonance-core-v2.3-experimental"
assert CONFIG["resource_confirmation_ticks"]==2
print("CORE_V23_SOURCE_PIN_AND_IMPORT_PASS")
