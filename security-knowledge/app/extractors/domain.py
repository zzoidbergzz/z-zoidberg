"""Extractor: domain names."""
import re
from typing import Any

DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


def extract(text: str) -> list[dict[str, Any]]:
    results = []
    for m in DOMAIN_PATTERN.finditer(text):
        val = m.group().lower()
        if "." in val and not val.replace(".", "").isdigit():
            results.append({"kind": "domain", "value": val})
    return results
