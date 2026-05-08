from __future__ import annotations
import re

BRACKETED_PUNCTUATION_RE = re.compile(r"[\[\(\{]\s*([.:/@])\s*[\]\)\}]")
BRACKETED_WORD_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)[\[\(\{]\s*dot\s*[\]\)\}]"), "."),
    (re.compile(r"(?i)[\[\(\{]\s*at\s*[\]\)\}]"), "@"),
)
SCHEME_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)^hxxps"), "https"),
    (re.compile(r"(?i)^hxxp"), "http"),
)

def normalize_indicator(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    for pattern, replacement in SCHEME_REPLACEMENTS:
        value = pattern.sub(replacement, value)
    value = BRACKETED_PUNCTUATION_RE.sub(r"\1", value)
    for pattern, replacement in BRACKETED_WORD_REPLACEMENTS:
        value = pattern.sub(replacement, value)
    return value.strip()
