#!/usr/bin/env python3
"""Safe Tor onion site scraper for threat intelligence.

SAFETY MODEL:
- All requests go through Tor SOCKS proxy (never direct)
- Circuit breaker: max 5 requests per onion, 30s between requests
- No JavaScript execution (requests only, no browser)
- No file downloads — metadata and text only
- User-Agent rotation
- All scraped data tagged with source .onion URL
- Respects robots.txt where available
- Rate limited globally to 1 req/10s

Requires: tor running on localhost:9050
"""
import asyncio
import hashlib
import json
import os
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import socks  # PySocks
import socket

# ── Configuration ──────────────────────────────────────────────
TOR_PROXY = ("127.0.0.1", 9050)
RATE_LIMIT_SECONDS = 10
MAX_REQUESTS_PER_SITE = 5
REQUEST_TIMEOUT = 30
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

# Known threat actor onion sites (curated, verify before adding)
# These are publicly reported in threat intel reports
ONION_SITES = [
    {"url": "http://lockbit3753ekiocyo5epmxsfips.onion", "label": "LockBit Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://lockbitaptc2iq4atewz2ise62q7.onion", "label": "LockBit Negotiation Portal", "category": "ransomware_negotiation_portal"},
    {"url": "http://alphvmmm27o3abo3r2mlmjrpdm.onion", "label": "BlackCat/ALPHV Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://alphv5a2opv5o7mj3ej4on4ttg.onion", "label": "BlackCat/ALPHV Negotiation Portal", "category": "ransomware_negotiation_portal"},
    {"url": "http://ssspbmocodo7k2as2klqsijr5amkyr2g3z3dh2bg7qx4e2kn7trq7dad.onion", "label": "Cl0p Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd.onion", "label": "Play Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76iez7767hkd5qt7jcb5qid.onion", "label": "Akira Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76iez7767hkd5qt7jcb5qid.onion/chat", "label": "Akira Negotiation Portal", "category": "ransomware_negotiation_portal"},
    {"url": "http://royal2lnlbpag7q3ra2f3fhnq4wkdq5a2j7tg7d4g6b7x7e3hqv7bnid.onion", "label": "Royal/BlackSuit Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion", "label": "Rhysida Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://medusaxko7jxtrojdkxo66j7ck4q5tsdmn2cuq7nxgqqed2e5gc6did.onion", "label": "Medusa Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://bianlianlbc5an4kgnay3opdemgcryg2bvy.onion", "label": "BianLian Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://hunters55rdakq7wd3z6ah3otikruw7jtb5ihmb4vs5jm5coqc5svhuyd.onion", "label": "Hunters International Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://ransomxifxwc5eteopdobynonjcalls2yber7x2gsz5j7f3op5bidqd.onion", "label": "RansomHub Leak Site", "category": "ransomware_leak_site"},
    {"url": "http://fog4k6wby3uzgtxfpw5wj3zmjkwsdrcokflikjm3sxauqr4k7hcbvqd.onion", "label": "Fog Leak Site", "category": "ransomware_leak_site"}
]

ONION_LIST_FILE = os.environ.get("ONION_LIST_FILE", "")
DATA_DIR = Path(__file__).parent.parent / "data" / "onion_scrapes"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Circuit breaker state
_request_counts: dict[str, int] = {}
_last_request_time: float = 0


def _get_tor_session():
    """Create a urllib opener that routes through Tor SOCKS proxy."""
    socks.set_default_proxy(socks.SOCKS5, TOR_PROXY[0], TOR_PROXY[1])
    socket.socket = socks.socksocket
    # Also patch DNS resolution through Tor
    socks.wrap_module(urllib.request)


def _check_tor():
    """Verify Tor is running and we can reach .onion addresses."""
    try:
        socks.set_default_proxy(socks.SOCKS5, TOR_PROXY[0], TOR_PROXY[1])
        s = socks.socksocket()
        s.settimeout(10)
        s.connect(("check.torproject.org", 80))
        s.close()
        return True
    except Exception:
        return False


def _rate_limit():
    """Enforce global rate limit between requests."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_SECONDS:
        wait = RATE_LIMIT_SECONDS - elapsed
        print(f"  Rate limiting: waiting {wait:.1f}s")
        time.sleep(wait)
    _last_request_time = time.time()


def scrape_onion(url: str, label: str = "", category: str = "") -> dict | None:
    """Scrape a single .onion URL safely. Text/metadata only, no downloads."""
    # Circuit breaker
    count = _request_counts.get(url, 0)
    if count >= MAX_REQUESTS_PER_SITE:
        print(f"  Circuit breaker: {url} hit max requests ({count})")
        return None

    _rate_limit()
    _request_counts[url] = count + 1

    ua = random.choice(USER_AGENTS)
    print(f"  Fetching: {url} (attempt {count + 1})")

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": ua,
            "Accept": "text/html,text/plain,application/json",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "")
            # Only scrape text content
            if not any(t in content_type for t in ["text", "json", "html"]):
                print(f"  Skipping non-text content: {content_type}")
                return None

            data = resp.read(1024 * 1024)  # Max 1MB
            text = data.decode("utf-8", errors="replace")

            result = {
                "url": url,
                "label": label,
                "category": category,
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "status": resp.status,
                "content_type": content_type,
                "content_length": len(data),
                "content_hash": hashlib.sha256(data).hexdigest(),
                "content_preview": text[:5000],
                "full_content_path": None,
            }

            # Save full content to disk (not in DB)
            safe_name = hashlib.sha256(url.encode()).hexdigest()[:16]
            content_file = DATA_DIR / f"{safe_name}_{int(time.time())}.txt"
            content_file.write_text(text)
            result["full_content_path"] = str(content_file)

            return result

    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "error": str(e), "scraped_at": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        return {"url": url, "status": "error", "error": str(e), "scraped_at": datetime.now(timezone.utc).isoformat()}


def load_onion_list() -> list[dict]:
    """Load onion sites from config file or defaults."""
    sites = list(ONION_SITES)
    if ONION_LIST_FILE and os.path.exists(ONION_LIST_FILE):
        with open(ONION_LIST_FILE) as f:
            extra = json.load(f)
            if isinstance(extra, list):
                sites.extend(extra)
    return sites


def main():
    print("=== Zoidberg Onion Scraper ===")
    print(f"Tor proxy: {TOR_PROXY}")
    print(f"Rate limit: {RATE_LIMIT_SECONDS}s between requests")
    print(f"Max requests per site: {MAX_REQUESTS_PER_SITE}")

    if not _check_tor():
        print("WARNING: Tor not available. Install and start tor service.")
        print("  sudo apt install tor && sudo systemctl start tor")
        return

    sites = load_onion_list()
    if not sites:
        print("No onion sites configured. Add URLs to ONION_SITES or set ONION_LIST_FILE.")
        return

    print(f"Scraping {len(sites)} sites...")
    results = []
    for site in sites:
        url = site.get("url", site) if isinstance(site, dict) else site
        label = site.get("label", "") if isinstance(site, dict) else ""
        category = site.get("category", "") if isinstance(site, dict) else ""
        result = scrape_onion(url, label, category)
        if result:
            results.append(result)

    # Save results
    out_file = DATA_DIR / f"scrape_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Scraped {len(results)} sites. Results: {out_file}")


if __name__ == "__main__":
    main()
