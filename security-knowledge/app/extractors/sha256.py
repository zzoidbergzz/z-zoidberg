"""Extractor: SHA-256 hashes."""
import re
from typing import Any

SHA256_PATTERN = re.compile(r'\b[0-9a-fA-F]{64}\b')


def extract(text: str) -> list[dict[str, Any]]:
    return [{"kind": "hash", "value": m.group().lower()} for m in SHA256_PATTERN.finditer(text)]
