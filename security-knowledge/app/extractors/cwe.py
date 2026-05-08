"""Extractor: CWE identifiers (e.g. CWE-79)."""
import re
from typing import Any

CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)


def extract(text: str) -> list[dict[str, Any]]:
    return [{"kind": "cwe", "value": m.group().upper()} for m in CWE_PATTERN.finditer(text)]

