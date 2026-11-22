"""Portable counterpart for frozen Core V2.3 input contracts."""
from pathlib import Path
try:
    from .common import canonical,signals
except ImportError:
    from common import canonical,signals
RESOURCE_DOMAIN = b"Resonance resource observation v1\x00"
RESOURCE_FIELDS = frozenset(("seq","monotonic_ns","utc_ns","cpu_ns","rss_bytes",
                             "disk_used_bytes","disk_total_bytes"))
