"""Extractor: MITRE ATT&CK Technique IDs (e.g. T1566, T1566.001)."""
import re
from typing import Any

# Technique IDs are T followed by 4 digits, optionally a sub-technique like .001.
# Word boundary on the right is loose so parentheses / punctuation work.
TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract(text: str) -> list[dict[str, Any]]:
    """Extract MITRE ATT&CK technique references from text."""
    return [{"kind": "technique", "value": m.group()} for m in TECHNIQUE_PATTERN.finditer(text)]

