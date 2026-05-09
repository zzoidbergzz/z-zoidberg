"""Defang/refang normalizer for IOC text.

Handles the common ways analysts and threat-intel feeds neutralise
indicators so they don't auto-link in chat/email/PDFs. References:
  - CISA / MITRE / SANS defang conventions
  - https://github.com/ninoseki/iocingestor (community patterns)
  - Real-world feeds: PaloAlto Unit42, Mandiant, Recorded Future, Volexity
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Scheme refanging — apply at start *and* anywhere mid-string (URLs in prose).
# ---------------------------------------------------------------------------
_SCHEME_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    # hxxp/hXXp/hXxP → http  (case-insensitive); also handles hXXps
    (re.compile(r"(?i)\bhxxps\b"), "https"),
    (re.compile(r"(?i)\bhxxp\b"), "http"),
    # Some feeds write "meow://" as a generic defang
    (re.compile(r"(?i)\bmeow(?=://)"), "http"),
    # fxp:// → ftp://
    (re.compile(r"(?i)\bfxp(?=://)"), "ftp"),
    # Defanged scheme separators: http[://]example, http[:]//example,
    # http[/]/example, http\:\/\/example, http://\\example, https//example
    (re.compile(r"(?i)\b(https?|ftp)\s*[\[\(\{]\s*://\s*[\]\)\}]"), r"\1://"),
    (re.compile(r"(?i)\b(https?|ftp)\s*[\[\(\{]\s*//\s*[\]\)\}]"), r"\1//"),
    (re.compile(r"(?i)\b(https?|ftp)\s*[\[\(\{]\s*:\s*[\]\)\}]"), r"\1:"),
    (re.compile(r"(?i)\b(https?|ftp):\s*[\[\(\{]\s*/\s*[\]\)\}]\s*[\[\(\{]\s*/\s*[\]\)\}]"), r"\1://"),
    (re.compile(r"(?i)\b(https?|ftp)\\:\\/\\/"), r"\1://"),
    (re.compile(r"(?i)\b(https?|ftp)://\\\\"), r"\1://"),
    # https// (missing colon) → https://   — only when followed by what looks like a host
    (re.compile(r"(?i)\b(https?|ftp)//(?=[a-z0-9])"), r"\1://"),
)

# ---------------------------------------------------------------------------
# Bracketed punctuation:
#   [.] (.) {.}   →  .
#   [:] (:)       →  :
#   [/] (/)       →  /
#   [@] (@)       →  @
#   [://]         →  ://      (already handled above for schemes; also generic)
# Allow optional surrounding whitespace and any of  []  ()  {}  <>  .
# ---------------------------------------------------------------------------
_BRACKET_OPEN = r"[\[\(\{<]"
_BRACKET_CLOSE = r"[\]\)\}>]"

_BRACKETED_SINGLE_PUNC_RE = re.compile(
    rf"{_BRACKET_OPEN}\s*([.:/@])\s*{_BRACKET_CLOSE}"
)
_BRACKETED_TRIPLE_SLASH_RE = re.compile(
    rf"{_BRACKET_OPEN}\s*://\s*{_BRACKET_CLOSE}"
)
_BRACKETED_DOUBLE_SLASH_RE = re.compile(
    rf"{_BRACKET_OPEN}\s*//\s*{_BRACKET_CLOSE}"
)

# ---------------------------------------------------------------------------
# Word substitutions: dot/at/colon/slash spelled out.
# Match either bracketed forms ([dot], (DOT), {dot})
# OR space-bounded words used to break up an indicator
# ("evil dot example dot com", "user at example dot com").
# We're conservative on the bare-word form: it must be lowercase or uppercase,
# and surrounded by non-alpha characters (whitespace or punctuation), to avoid
# eating words like "the at the" in prose.
# ---------------------------------------------------------------------------
_BRACKETED_WORD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"(?i){_BRACKET_OPEN}\s*dot\s*{_BRACKET_CLOSE}"), "."),
    (re.compile(rf"(?i){_BRACKET_OPEN}\s*at\s*{_BRACKET_CLOSE}"), "@"),
    (re.compile(rf"(?i){_BRACKET_OPEN}\s*colon\s*{_BRACKET_CLOSE}"), ":"),
    (re.compile(rf"(?i){_BRACKET_OPEN}\s*slash\s*{_BRACKET_CLOSE}"), "/"),
    (re.compile(rf"(?i){_BRACKET_OPEN}\s*at\s*sign\s*{_BRACKET_CLOSE}"), "@"),
)

_BARE_WORD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # " dot " between alphanumerics → "."   (e.g. evil dot example dot com)
    (re.compile(r"(?i)(?<=[a-z0-9])\s+dot\s+(?=[a-z0-9])"), "."),
    # NOTE: deliberately no bare " at " rule — too many false positives on
    # English prose ("look at the dot above"). Bracketed [at]/(at) handled
    # by `_BRACKETED_WORD_PATTERNS`, which is the form real-world feeds use.
)

# ---------------------------------------------------------------------------
# Backslash-escaped dots/at/colon ( evil\.example\.com, user\@example\.com )
# Typical of regex-style defanging.
# ---------------------------------------------------------------------------
_BACKSLASH_ESC_RE = re.compile(r"\\([.:/@])")

# ---------------------------------------------------------------------------
# Whitespace-around-dot defang: "8 . 8 . 8 . 8" or "evil . example . com".
# Conservative: only collapse if the pattern looks IPv4-ish or domain-ish
# (alphanumerics on both sides separated only by spaces and a dot).
# Applied repeatedly because each pass collapses one separator.
# ---------------------------------------------------------------------------
_SPACED_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\s+\.\s+(?=[A-Za-z0-9])")
_SPACED_AT_RE = re.compile(r"(?<=[A-Za-z0-9])\s+@\s+(?=[A-Za-z0-9])")

# Some feeds wrap the whole IOC in matched delimiters: <evil.com>, "evil.com",
# 'evil.com', `evil.com`, (evil.com).  Strip a single matched outer pair.
_OUTER_WRAP_RE = re.compile(
    r"^\s*([\<\(\[\{\"\'\`])(.+?)([\>\)\]\}\"\'\`])\s*$"
)
_OUTER_WRAP_PAIRS = {
    "<": ">", "(": ")", "[": "]", "{": "}", '"': '"', "'": "'", "`": "`",
}


def _strip_outer_wrap(value: str) -> str:
    m = _OUTER_WRAP_RE.match(value)
    if not m:
        return value
    open_c, inner, close_c = m.group(1), m.group(2), m.group(3)
    if _OUTER_WRAP_PAIRS.get(open_c) != close_c:
        return value
    # Only strip if the inner doesn't itself contain unbalanced brackets that
    # would change meaning — keep this dumb-and-safe.
    return inner.strip()


def normalize_indicator(raw: str) -> str:
    """Refang a single indicator string.

    Idempotent: ``normalize_indicator(normalize_indicator(x)) == normalize_indicator(x)``.

    Handles defang patterns commonly used in threat-intel reports::

        evil[.]com, evil(.)com, evil{.}com, evil<.>com
        evil[dot]com, evil(DOT)com, evil dot com (between alnums)
        user[at]example.com, user(at)example.com, user at example.com
        hxxp://, hxxps://, hXXp://, meow://, fxp://
        http[://]evil.com, http[:]//evil.com, https//evil.com
        evil\\.example\\.com (backslash escapes)
        8 . 8 . 8 . 8 (spaced dots)
        <evil.com>, "evil.com", (evil.com) (outer wrap)
    """
    if raw is None:
        return ""
    value = str(raw).strip()
    if not value:
        return ""

    # 1. Strip a single matched outer wrap so brackets used as quotes don't
    #    confuse later patterns.  Run twice in case of nested ((evil.com)).
    value = _strip_outer_wrap(value)
    value = _strip_outer_wrap(value)

    # 2. Scheme refanging (hxxp, meow, fxp, defanged separators).
    for pattern, replacement in _SCHEME_REPLACEMENTS:
        value = pattern.sub(replacement, value)

    # 3. Bracketed punctuation: [://], [//], [.], [:], [/], [@]
    value = _BRACKETED_TRIPLE_SLASH_RE.sub("://", value)
    value = _BRACKETED_DOUBLE_SLASH_RE.sub("//", value)
    value = _BRACKETED_SINGLE_PUNC_RE.sub(r"\1", value)

    # 4. Bracketed words: [dot], [at], [colon], [slash]
    for pattern, replacement in _BRACKETED_WORD_PATTERNS:
        value = pattern.sub(replacement, value)

    # 5. Bare " dot "/" at " between alphanumerics
    for pattern, replacement in _BARE_WORD_PATTERNS:
        # Run repeatedly — each pass collapses one occurrence and may expose
        # the next ("a dot b dot c" needs two passes).
        prev = None
        while prev != value:
            prev = value
            value = pattern.sub(replacement, value)

    # 6. Backslash escapes: \. \: \/ \@
    value = _BACKSLASH_ESC_RE.sub(r"\1", value)

    # 7. Spaced dots/ats ("8 . 8 . 8 . 8", "user @ example.com")
    prev = None
    while prev != value:
        prev = value
        value = _SPACED_DOT_RE.sub(".", value)
        value = _SPACED_AT_RE.sub("@", value)

    return value.strip()


# Quick "does this even look defanged?" predicate, used by the search router
# to decide whether to also try the refanged form of a query.
_DEFANG_HINTS_RE = re.compile(
    r"(?ix)"
    r"(?: \[\s*\.\s*\] | \(\s*\.\s*\) | \{\s*\.\s*\}"
    r"  | \[\s*at\s*\] | \(\s*at\s*\) | \[\s*dot\s*\] | \(\s*dot\s*\)"
    r"  | \bhxxps?\b | \bmeow:// | \bfxp://"
    r"  | \\\. | \[\s*://\s*\] | \[\s*//\s*\]"
    r"  | (?<=\d)\s+\.\s+(?=\d)"
    r")"
)


def looks_defanged(value: str) -> bool:
    """Return True if *value* contains any common defang pattern."""
    return bool(value) and bool(_DEFANG_HINTS_RE.search(value))
