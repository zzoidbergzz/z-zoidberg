"""Defang/refang normalizer + extractor tests.

These cover the patterns we see in real-world threat-intel pastes:
CISA advisories, Mandiant blog posts, Unit42 PDFs, MISP exports, Discord chat
snippets, etc. If a new pattern shows up in the wild that we miss, add it here.
"""
from __future__ import annotations

import pytest

from app.lookup.classifier import classify_input
from app.lookup.extractor import extract_iocs
from app.lookup.normalizer import looks_defanged, normalize_indicator


# ---------------------------------------------------------------------------
# normalize_indicator: bracketed-punctuation defangs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("8[.]8[.]8[.]8", "8.8.8.8"),
        ("8(.)8(.)8(.)8", "8.8.8.8"),
        ("8{.}8{.}8{.}8", "8.8.8.8"),
        ("8<.>8<.>8<.>8", "8.8.8.8"),
        ("evil[.]example[.]com", "evil.example.com"),
        ("evil[.]EXAMPLE[.]com", "evil.EXAMPLE.com"),
        ("user[at]example[.]com", "user@example.com"),
        ("user(AT)example(DOT)com", "user@example.com"),
        ("user [ at ] example [ dot ] com", "user@example.com"),
        ("evil[dot]example[dot]com", "evil.example.com"),
        ("EVIL[DOT]EXAMPLE[DOT]COM", "EVIL.EXAMPLE.COM"),
    ],
)
def test_bracket_defangs(raw: str, expected: str) -> None:
    assert normalize_indicator(raw) == expected


# ---------------------------------------------------------------------------
# normalize_indicator: scheme refanging
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("hxxp://evil.com/x", "http://evil.com/x"),
        ("hxxps://evil.com/x", "https://evil.com/x"),
        ("hXXp://evil.com", "http://evil.com"),
        ("hXXPS://evil.com", "https://evil.com"),
        ("meow://evil.com", "http://evil.com"),
        ("fxp://files.evil.com/x", "ftp://files.evil.com/x"),
        ("hxxps://evil[.]com/path", "https://evil.com/path"),
        ("hxxp[://]evil[.]com", "http://evil.com"),
        ("http[:]//evil[.]com", "http://evil.com"),
        ("http[/]/evil[.]com", "http//evil.com"),  # missing colon stays — caller can decide
        ("https//evil.com", "https://evil.com"),  # purely missing-colon defang
        ("https:\\/\\/evil.com", "https://evil.com"),
    ],
)
def test_scheme_refang(raw: str, expected: str) -> None:
    assert normalize_indicator(raw) == expected


# ---------------------------------------------------------------------------
# normalize_indicator: backslash + spaced + bare-word defangs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("evil\\.example\\.com", "evil.example.com"),
        ("user\\@example\\.com", "user@example.com"),
        ("8 . 8 . 8 . 8", "8.8.8.8"),
        ("evil . example . com", "evil.example.com"),
        ("evil dot example dot com", "evil.example.com"),
        # Bare " at " is intentionally not refanged (too prose-ambiguous);
        # bracketed [at] / (at) defangs ARE refanged — see tests above.
    ],
)
def test_misc_defangs(raw: str, expected: str) -> None:
    assert normalize_indicator(raw) == expected


def test_outer_wrap_stripped() -> None:
    assert normalize_indicator("<evil.com>") == "evil.com"
    assert normalize_indicator('"evil.com"') == "evil.com"
    assert normalize_indicator("(evil.com)") == "evil.com"
    assert normalize_indicator("`evil.com`") == "evil.com"


def test_idempotent() -> None:
    samples = [
        "8[.]8[.]8[.]8",
        "hxxps://evil[dot]com/path",
        "user[at]example[.]com",
        "evil\\.example\\.com",
    ]
    for s in samples:
        once = normalize_indicator(s)
        twice = normalize_indicator(once)
        assert once == twice, f"not idempotent for {s!r}: {once!r} → {twice!r}"


def test_prose_doesnt_produce_false_iocs() -> None:
    """The extractor must not surface IOCs from plain English sentences.
    The normalizer itself may aggressively collapse bare 'at'/'dot' (it
    runs per-token, not over paragraphs) — what matters is that the
    extractor → classifier pipeline rejects the result."""
    prose = "Look at the dot above and below. Click here for more info."
    iocs = extract_iocs(prose)
    assert iocs == [], f"expected no IOCs from prose, got {iocs}"


# ---------------------------------------------------------------------------
# looks_defanged predicate
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("8[.]8[.]8[.]8", True),
        ("hxxps://evil.com", True),
        ("user[at]example.com", True),
        ("8.8.8.8", False),
        ("https://example.com", False),
        ("just some text", False),
    ],
)
def test_looks_defanged(raw: str, expected: bool) -> None:
    assert looks_defanged(raw) is expected


# ---------------------------------------------------------------------------
# classify_input goes via normalize, so defanged inputs classify correctly.
# ---------------------------------------------------------------------------
def test_classify_defanged_ip() -> None:
    assert classify_input("8[.]8[.]8[.]8") == {"type": "ip", "value": "8.8.8.8"}


def test_classify_defanged_url() -> None:
    cls = classify_input("hxxps://evil[.]example[.]com/path")
    assert cls == {"type": "url", "value": "https://evil.example.com/path"}


def test_classify_defanged_email() -> None:
    cls = classify_input("user[at]example[.]com")
    assert cls == {"type": "email", "value": "user@example.com"}


def test_classify_defanged_domain() -> None:
    cls = classify_input("evil[dot]example[dot]com")
    assert cls == {"type": "domain", "value": "evil.example.com"}


# ---------------------------------------------------------------------------
# extract_iocs: bulk text scanning
# ---------------------------------------------------------------------------
def test_extract_from_mixed_blob() -> None:
    blob = """
    Threat actor used hxxps://evil[.]example[.]com/payload.exe to drop
    a beacon to 8[.]8[.]8[.]8 and 1.1.1.1 (sha256
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855).
    Reachable via user[at]evil.com — see CVE-2024-3400 for context.
    Also 192 . 168 . 1 . 1 was contacted.
    """
    iocs = extract_iocs(blob)
    pairs = {(i["type"], i["value"]) for i in iocs}
    assert ("ip", "8.8.8.8") in pairs
    assert ("ip", "1.1.1.1") in pairs
    assert ("ip", "192.168.1.1") in pairs
    assert ("url", "https://evil.example.com/payload.exe") in pairs
    assert ("email", "user@evil.com") in pairs
    assert ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in pairs
    assert ("cve", "CVE-2024-3400") in pairs


def test_extract_dedupes() -> None:
    blob = "8.8.8.8 and 8[.]8[.]8[.]8 and 8 . 8 . 8 . 8"
    iocs = extract_iocs(blob)
    ips = [i for i in iocs if i["type"] == "ip"]
    assert len(ips) == 1
    assert ips[0]["value"] == "8.8.8.8"


def test_extract_empty() -> None:
    assert extract_iocs("") == []
    assert extract_iocs("   \n\n  ") == []


def test_extract_line_separated() -> None:
    blob = "8[.]8[.]8[.]8\nhxxps://evil.com\nuser[at]example.com"
    iocs = extract_iocs(blob)
    types = {i["type"] for i in iocs}
    assert types == {"ip", "url", "email"}
