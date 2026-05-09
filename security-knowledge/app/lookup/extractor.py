"""Bulk IOC extractor: scan a blob of free-text and pull out indicators.

Built on top of ``app.lookup.normalizer.normalize_indicator`` and
``app.lookup.classifier.classify_input`` so the same defang-handling rules
that power single-IOC lookup also drive the bulk extractor.

Usage::

    from app.lookup.extractor import extract_iocs
    iocs = extract_iocs("Pasted threat report ...")
    # → [{"value": "8.8.8.8", "type": "ip", "raw": "8[.]8[.]8[.]8"}, ...]

Returned items are deduplicated by (type, value) and preserve insertion order.
"""
from __future__ import annotations

import re
from typing import Iterable

from app.lookup.classifier import classify_input
from app.lookup.normalizer import looks_defanged, normalize_indicator

# Greedy candidate scanner: anything that *could* be an IOC after we glue
# defang fragments back together. We cast a wide net here and let the
# classifier reject non-IOC tokens.
#
# Notes on the regex:
#   • Each character class includes the bracketed-defang chars `[]()<>{}`
#     plus `\` so we don't split tokens like `evil[.]example[.]com`.
#   • We allow whitespace inside `[ . ]` style defangs but NOT outside —
#     bare whitespace splits candidates.
#   • CVE/CWE/EDB-style identifiers and bare hashes are picked up by the
#     more permissive `_HEX_RE` and `_ID_RE` paths below.
_CANDIDATE_RE = re.compile(
    r"""
    (?:
        # URL-ish: starts with optional scheme (possibly defanged), then host bits
        (?: (?:hxxps?|https?|ftp|fxp|meow) [\[\(\{<]? [:\\/]+ [\]\)\}>]? )?
        [A-Za-z0-9]                       # must start with alnum
        [A-Za-z0-9._%+\-:/?#&=@~\[\]\(\)\{\}<>\\]*  # body
        [A-Za-z0-9\)\]\}>/]               # must end on alnum or closing bracket / slash
    )
    """,
    re.VERBOSE,
)

# Bare hex hash (md5/sha1/sha256) — picked up by the candidate scanner too,
# but easier to spot directly when surrounded by punctuation.
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

# Common identifier patterns we want to surface even though they're not real
# "indicators" in the IOC sense. They're useful to a researcher pasting
# bulk text into a parser.
_ID_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    ("cwe", re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)),
    ("attack", re.compile(r"\b(?:T|TA|S|G|M|DS|C)\d{4}(?:\.\d{3})?\b")),
    ("exploitdb", re.compile(r"\bEDB-(?:ID:?)?\s*\d+\b", re.IGNORECASE)),
    ("ghsa", re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)),
)

# Token splitter for line-oriented input where each line/comma is one IOC.
# Used as a fast-path before the full free-text scanner.
_LINE_SPLIT_RE = re.compile(r"[\r\n,;]+")


def _classify_one(token: str) -> dict[str, str] | None:
    """Run a token through normalize → classify; drop anything we can't type."""
    token = token.strip().rstrip(".,;:)>]}\"'`")
    if len(token) < 4:
        return None
    norm = normalize_indicator(token)
    if not norm:
        return None
    # Identifier short-circuit: classifier doesn't know about CVE/CWE/ATT&CK
    # IDs but we want to surface them verbatim from bulk pastes.
    for kind, rx in _ID_RES:
        if rx.fullmatch(norm):
            return {"value": norm.upper() if kind in ("cve", "cwe", "ghsa", "exploitdb") else norm,
                    "type": kind, "raw": token}
    cls = classify_input(norm)  # already runs normalize internally — cheap & idempotent
    if cls["type"] in ("empty", "unknown", "username"):
        # `username` is too noisy for free-text scanning (matches every word).
        # Singleton lookups still expose it; we just don't surface it here.
        return None
    # Reject results whose "value" is multi-token — the classifier's URL/email
    # regexes can match a whole prose line if it happens to start with a scheme,
    # producing values like "https://evil.com 8.8.8.8 ..." which are obviously
    # not single IOCs.
    if any(c.isspace() for c in cls["value"]):
        return None
    return {"value": cls["value"], "type": cls["type"], "raw": token}


def _iter_candidates(text: str) -> Iterable[str]:
    """Yield candidate substrings from *text* worth running through the classifier."""
    # 1. Line/comma splits — fast path for "one per line" pastes.
    for chunk in _LINE_SPLIT_RE.split(text):
        chunk = chunk.strip()
        if not chunk:
            continue
        yield chunk
        # Only re-yield the normalized form + rescan when the chunk actually
        # looks defanged. Otherwise we mangle plain prose into bogus IOCs
        # (e.g. "Look at the dot above" → "the.above" → false-positive domain).
        if looks_defanged(chunk):
            normed = normalize_indicator(chunk)
            if normed and normed != chunk:
                yield normed
                for m in _CANDIDATE_RE.finditer(normed):
                    yield m.group(0)
    # 2. Free-text scan — pulls IOCs out of prose.
    for m in _CANDIDATE_RE.finditer(text):
        yield m.group(0)
    # 3. Bare hashes (the candidate regex usually catches them, but belt+braces).
    for m in _HEX_RE.finditer(text):
        yield m.group(0)
    # 4. Known identifier patterns (CVE, CWE, ATT&CK, EDB, GHSA).
    for kind, rx in _ID_RES:
        for m in rx.finditer(text):
            yield m.group(0)


def extract_iocs(text: str, *, limit: int = 500) -> list[dict[str, str]]:
    """Extract and classify IOCs from a blob of text.

    Returns a deduplicated list of ``{"value", "type", "raw"}`` dicts in the
    order each IOC first appeared. Up to *limit* unique IOCs are returned.
    """
    if not text or not text.strip():
        return []

    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []

    for cand in _iter_candidates(text):
        item = _classify_one(cand)
        if item is None:
            continue
        key = (item["type"], item["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break

    return out
