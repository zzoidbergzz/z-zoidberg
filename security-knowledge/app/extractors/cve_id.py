"""Extractor: CVE identifiers."""
import re
from typing import Any

CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)


def extract(text: str) -> list[dict[str, Any]]:
    return [{"kind": "cve", "value": m.group()} for m in CVE_PATTERN.finditer(text)]
