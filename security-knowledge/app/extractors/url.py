"""Extractor: URLs."""
import re
from typing import Any

URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')


def extract(text: str) -> list[dict[str, Any]]:
    return [{"kind": "url", "value": m.group()} for m in URL_PATTERN.finditer(text)]
