"""Deduplication: content hash, canonical URL, fuzzy title, IOC overlap."""

from __future__ import annotations
import hashlib
import logging
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlunparse
from typing import Optional

logger = logging.getLogger(__name__)

# Fuzzy title match threshold
TITLE_SIMILARITY_THRESHOLD = 0.85

# IOC overlap threshold for dedup
IOC_OVERLAP_THRESHOLD = 0.7


def compute_content_hash(title: str, body: str) -> str:
    """Compute SHA-256 hash of title + body."""
    content = f"{title}\n{body}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def normalize_url(url: str) -> str:
    """Normalize URL for deduplication."""
    try:
        parsed = urlparse(url)
        # Remove fragment, trailing slash, common tracking params
        path = parsed.path.rstrip("/")
        # Remove common tracking parameters
        clean_params = []
        if parsed.query:
            for param in parsed.query.split("&"):
                if not param.startswith(("utm_", "ref=", "source=")):
                    clean_params.append(param)
        query = "&".join(clean_params)
        return urlunparse((parsed.scheme, parsed.netloc.lower(), path, parsed.params, query, ""))
    except Exception:
        return url


def fuzzy_title_match(title1: str, title2: str, threshold: float = TITLE_SIMILARITY_THRESHOLD) -> bool:
    """Check if two titles are similar enough to be duplicates."""
    # Normalize
    t1 = re.sub(r'\s+', ' ', title1.lower().strip())
    t2 = re.sub(r'\s+', ' ', title2.lower().strip())

    if t1 == t2:
        return True

    ratio = SequenceMatcher(None, t1, t2).ratio()
    return ratio >= threshold


def ioc_overlap_score(iocs1: set, iocs2: set) -> float:
    """Calculate IOC overlap score between two sets."""
    if not iocs1 or not iocs2:
        return 0.0
    intersection = iocs1 & iocs2
    union = iocs1 | iocs2
    return len(intersection) / len(union) if union else 0.0


def is_duplicate(
    new_item: dict,
    existing_items: list[dict],
    check_url: bool = True,
    check_hash: bool = True,
    check_title: bool = True,
    check_ioc: bool = True,
) -> tuple[bool, Optional[str]]:
    """Check if a new item is a duplicate of any existing items.

    Returns (is_duplicate, reason).
    """
    new_url = normalize_url(new_item.get("url", ""))
    new_hash = new_item.get("hash_content", "")
    new_title = new_item.get("title_original", "")
    new_iocs = set(
        (new_item.get("extracted_iocs") or {}).get("ipv4", [])
        + (new_item.get("extracted_iocs") or {}).get("domains", [])
        + (new_item.get("extracted_iocs") or {}).get("sha256_hashes", [])
    )

    for existing in existing_items:
        # URL match
        if check_url and new_url:
            existing_url = normalize_url(existing.get("url", ""))
            if new_url == existing_url and new_url:
                return (True, "url_match")

        # Content hash match
        if check_hash and new_hash:
            if new_hash == existing.get("hash_content", ""):
                return (True, "content_hash_match")

        # Fuzzy title match
        if check_title and new_title:
            existing_title = existing.get("title_original", "")
            if fuzzy_title_match(new_title, existing_title):
                return (True, "fuzzy_title_match")

        # IOC overlap
        if check_ioc and new_iocs:
            existing_iocs = set(
                (existing.get("extracted_iocs") or {}).get("ipv4", [])
                + (existing.get("extracted_iocs") or {}).get("domains", [])
                + (existing.get("extracted_iocs") or {}).get("sha256_hashes", [])
            )
            if ioc_overlap_score(new_iocs, existing_iocs) >= IOC_OVERLAP_THRESHOLD:
                return (True, "ioc_overlap")

    return (False, None)
