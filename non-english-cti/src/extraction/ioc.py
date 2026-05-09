"""IOC extraction: IPs, domains, hashes, URLs, emails."""

from __future__ import annotations
import re
import logging
from typing import Optional

from ..models.record import IOCSet

logger = logging.getLogger(__name__)

# Regex patterns for IOC extraction
PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
        r'|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b',
        re.IGNORECASE
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:[a-zA-Z]{2,})\b'
    ),
    "url": re.compile(
        r'https?://[^\s<>"\')\]]+'
    ),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
}

# Domains to exclude (common false positives)
EXCLUDED_DOMAINS = {
    "example.com", "example.org", "localhost.com",
    "google.com", "microsoft.com", "github.com",
    "amazon.com", "cloudflare.com", "akamai.com",
}


def extract_iocs(text: str) -> IOCSet:
    """Extract IOCs from text.

    Returns IOCSet with all found indicators.
    """
    if not text:
        return IOCSet()

    iocs = IOCSet()

    # Extract hashes first (most specific) to avoid overlap with other patterns
    sha256_matches = set(PATTERNS["sha256"].findall(text))
    sha1_matches = set(PATTERNS["sha1"].findall(text)) - sha256_matches
    md5_matches = set(PATTERNS["md5"].findall(text)) - sha256_matches - sha1_matches

    iocs.sha256_hashes = sorted(sha256_matches)
    iocs.sha1_hashes = sorted(sha1_matches)
    iocs.md5_hashes = sorted(md5_matches)

    # Extract IPs
    iocs.ipv4 = sorted(set(PATTERNS["ipv4"].findall(text)))
    iocs.ipv6 = sorted(set(PATTERNS["ipv6"].findall(text)))

    # Extract URLs
    urls = set(PATTERNS["url"].findall(text))
    # Remove URLs that are just domains with http://
    domain_urls = {u for u in urls if re.match(r'https?://[^/]+/?$', u)}
    iocs.urls = sorted(urls - domain_urls)

    # Extract domains (excluding common false positives and URLs)
    domains = set(PATTERNS["domain"].findall(text))
    domains -= EXCLUDED_DOMAINS
    # Exclude domains that are part of URLs
    url_domains = set()
    for url in urls:
        match = re.match(r'https?://([^/]+)', url)
        if match:
            url_domains.add(match.group(1).split(":")[0])
    iocs.domains = sorted(domains - url_domains)

    # Extract emails
    iocs.email_addresses = sorted(set(PATTERNS["email"].findall(text)))

    return iocs
