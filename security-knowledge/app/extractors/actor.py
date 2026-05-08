"""Extractor: Threat-actor / APT group references.

Matches common naming conventions (APT##, FIN##, UNC####, TA####) plus a
small curated list of well-known group aliases.  This is intentionally
conservative — high-recall NER is the job of a downstream LLM enricher.
"""
import re
from typing import Any

_PATTERNS = [
    re.compile(r"\bAPT[- ]?\d{1,3}\b", re.IGNORECASE),
    re.compile(r"\bFIN\d{1,2}\b", re.IGNORECASE),
    re.compile(r"\bUNC\d{3,5}\b", re.IGNORECASE),
    re.compile(r"\bTA\d{3,5}\b"),
]

_NAMED_ACTORS = {
    "lazarus", "kimsuky", "turla", "sandworm", "fancy bear", "cozy bear",
    "equation group", "carbanak", "wizard spider", "scattered spider",
    "lapsus$", "lapsus", "mustang panda", "charming kitten", "volt typhoon",
    "salt typhoon", "midnight blizzard",
}


def extract(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for pat in _PATTERNS:
        for m in pat.finditer(text):
            out.append({"kind": "actor", "value": m.group().upper().replace(" ", "")})
    lower = text.lower()
    for name in _NAMED_ACTORS:
        if name in lower:
            out.append({"kind": "actor", "value": name.title()})
    return out

