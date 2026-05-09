"""Deterministic parsing helpers for onion-site content."""
from __future__ import annotations

import re
from collections.abc import Iterable

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_XMR_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{93,105}\b")
_TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_FILE_RE = re.compile(
    r"\b[a-zA-Z0-9._-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|bin|dat|tmp|zip|7z|rar|iso|msi)\b",
    re.IGNORECASE,
)
_RANSOM_RE = re.compile(
    r"(?:\$\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:k|m|b|million|billion))?|\b\d+(?:\.\d+)?\s?(?:BTC|XMR|ETH|USDT)\b)",
    re.IGNORECASE,
)
_VICTIM_LINE_RE = re.compile(
    r"\b(?:victim|company|organization|target|leaked|breached)\b\s*[:\-]\s*([A-Za-z0-9&'().,\- ]{3,120})",
    re.IGNORECASE,
)
_ORG_SUFFIX_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&'().,\- ]{2,80}\s(?:Inc|Corp|Corporation|Ltd|LLC|Group|Bank|University|Hospital|PLC|GmbH|S\.A\.|AG))\b"
)


def _unique(values: Iterable[str], *, max_items: int = 100) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        v = (raw or "").strip()
        if not v:
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
        if len(out) >= max_items:
            break
    return out


def _strip_html(raw: str) -> str:
    # Keep deterministic and dependency-free.
    text = re.sub(r"<script[^>]*>.*?</script>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_onion_findings(content: str) -> dict:
    text = _strip_html(content)

    victims = _unique(_VICTIM_LINE_RE.findall(text) + _ORG_SUFFIX_RE.findall(text), max_items=50)
    emails = _unique(_EMAIL_RE.findall(text), max_items=100)
    ips = _unique(_IPV4_RE.findall(text), max_items=100)
    domains = _unique(_DOMAIN_RE.findall(text), max_items=150)
    onion_links = _unique(_ONION_RE.findall(text), max_items=100)
    hashes = _unique(_SHA256_RE.findall(text) + _SHA1_RE.findall(text) + _MD5_RE.findall(text), max_items=200)
    binaries = _unique(_FILE_RE.findall(text), max_items=200)
    payment_addresses = _unique(
        _BTC_RE.findall(text) + _ETH_RE.findall(text) + _XMR_RE.findall(text) + _TRON_RE.findall(text),
        max_items=150,
    )
    ransom_amounts = _unique(_RANSOM_RE.findall(text), max_items=100)

    return {
        "victims": victims,
        "payment_addresses": payment_addresses,
        "emails": emails,
        "hashes": hashes,
        "ips": ips,
        "domains": domains,
        "onion_links": onion_links,
        "binaries": binaries,
        "ransom_amounts": ransom_amounts,
        "summary": {
            "victim_count": len(victims),
            "payment_address_count": len(payment_addresses),
            "binary_count": len(binaries),
            "ioc_count": len(hashes) + len(ips) + len(domains),
        },
    }

