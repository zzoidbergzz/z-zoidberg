"""Extractor: CPE 2.3 URIs."""
import re
from typing import Any

CPE_PATTERN = re.compile(r"\bcpe:2\.3:[aho]:[^\s,]+", re.IGNORECASE)


def extract(text: str) -> list[dict[str, Any]]:
    return [{"kind": "cpe", "value": m.group()} for m in CPE_PATTERN.finditer(text)]

