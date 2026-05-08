"""Extractor: IPv4 addresses."""
import re
from typing import Any

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')


def extract(text: str) -> list[dict[str, Any]]:
    return [{"kind": "ip", "value": m.group()} for m in IP_PATTERN.finditer(text)]
