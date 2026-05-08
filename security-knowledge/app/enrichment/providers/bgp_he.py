"""
bgp.he.net enrichment provider.

Scrapes Hurricane Electric's BGP Toolkit (https://bgp.he.net) to collect:
  - ASN name, description, country
  - IPv4 / IPv6 prefix announcements
  - BGP peer list (upstream/downstream/lateral)
  - Sibling ASNs (same organisation)

Supported entity kinds:
  - asn        → full ASN detail page
  - ip_address / ip → /ip/{addr} for route / containing ASN lookup
  - domain     → /dns/{fqdn} for origin-AS of A/AAAA records

Data is stored with a ``scraped_at`` timestamp so callers can decide when
to refresh (default TTL in config: BGP_HE_DAILY_BUDGET limits API hits).

Caveats:
  - bgp.he.net has no public API.  Scraping is best-effort and table
    structure may change.
  - We include a realistic User-Agent and respect a 3 s per-request delay
    to avoid hammering the server.
  - We do NOT store the raw HTML; only parsed structured data.
"""

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from bs4 import BeautifulSoup

from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

_BASE = "https://bgp.he.net"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; SecurityKnowledgeBot/1.0; "
        "+https://z.je/about)"
    ),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-GB,en;q=0.9",
}

# Polite scraping: wait at least this many seconds between requests
_MIN_INTERVAL = 3.0
_last_request_ts: float = 0.0
_scrape_lock = asyncio.Lock()


async def _polite_fetch(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """Fetch ``url`` with a rate-polite delay and basic error handling."""
    global _last_request_ts
    async with _scrape_lock:
        elapsed = time.monotonic() - _last_request_ts
        if elapsed < _MIN_INTERVAL:
            await asyncio.sleep(_MIN_INTERVAL - elapsed)
        try:
            resp = await client.get(url, headers=_HEADERS, timeout=30, follow_redirects=True)
            _last_request_ts = time.monotonic()
            if resp.status_code == 200:
                return resp
            logger.warning("bgp_he: non-200", url=url, status=resp.status_code)
            return None
        except httpx.HTTPError as exc:
            logger.error("bgp_he: http error", url=url, error=str(exc))
            return None


def _norm_asn(value: str) -> str | None:
    """Normalise an ASN value to an integer string, e.g. 'AS15169' → '15169'."""
    m = re.search(r"\d+", str(value))
    return m.group(0) if m else None


def _parse_prefix_table(soup: BeautifulSoup, table_id: str) -> list[dict]:
    """Parse a prefixes table by its HTML id.  Returns list of dicts."""
    table = soup.find("table", {"id": table_id})
    if not table:
        return []
    rows = []
    for tr in table.find_all("tr")[1:]:  # skip header
        cells = [td.get_text(strip=True) for td in tr.find_all("td")]
        if len(cells) >= 2:
            rows.append({"prefix": cells[0], "description": cells[1] if len(cells) > 1 else ""})
    return rows[:200]  # cap


def _parse_peer_table(soup: BeautifulSoup, table_id: str) -> list[dict]:
    """Parse a peer/neighbour table.  Returns list of {asn, name} dicts."""
    table = soup.find("table", {"id": table_id})
    if not table:
        return []
    rows = []
    for tr in table.find_all("tr")[1:]:
        cells = tr.find_all("td")
        if len(cells) >= 2:
            asn_text = cells[0].get_text(strip=True)
            name_text = cells[1].get_text(strip=True)
            asn_num = _norm_asn(asn_text)
            if asn_num:
                rows.append({"asn": asn_num, "name": name_text})
    return rows[:500]


async def _enrich_asn(client: httpx.AsyncClient, asn_num: str) -> dict[str, Any]:
    url = f"{_BASE}/AS{asn_num}"
    resp = await _polite_fetch(client, url)
    if resp is None:
        return {}

    soup = BeautifulSoup(resp.text, "lxml")
    result: dict[str, Any] = {
        "asn": f"AS{asn_num}",
        "source_url": url,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }

    # --- ASN name / description from <h1> or page title ---
    h1 = soup.find("h1")
    if h1:
        result["name"] = h1.get_text(strip=True)
    title = soup.find("title")
    if title:
        result["page_title"] = title.get_text(strip=True)

    # --- Info table (country, registry, etc.) ---
    # HE renders a <div id="description"> or similar with key/value pairs
    desc_div = soup.find("div", {"id": "description"})
    if desc_div:
        result["description"] = desc_div.get_text(separator=" ", strip=True)[:1000]

    # RIR / country cells often in a small table near the top
    info_table = soup.find("table", {"id": "asinfo"})
    if info_table:
        for tr in info_table.find_all("tr"):
            cells = tr.find_all("td")
            if len(cells) == 2:
                key = cells[0].get_text(strip=True).lower().replace(" ", "_")
                val = cells[1].get_text(strip=True)
                result[key] = val

    # --- IPv4 / IPv6 prefixes ---
    result["ipv4_prefixes"] = _parse_prefix_table(soup, "table_prefixes4")
    result["ipv6_prefixes"] = _parse_prefix_table(soup, "table_prefixes6")

    # --- BGP peers (upstream / downstream / lateral) ---
    result["peers_ipv4"]  = _parse_peer_table(soup, "table_peers4")
    result["peers_ipv6"]  = _parse_peer_table(soup, "table_peers6")
    result["upstreams_ipv4"]   = _parse_peer_table(soup, "table_upstreams4")
    result["upstreams_ipv6"]   = _parse_peer_table(soup, "table_upstreams6")
    result["downstreams_ipv4"] = _parse_peer_table(soup, "table_downstreams4")
    result["downstreams_ipv6"] = _parse_peer_table(soup, "table_downstreams6")

    # Derive a flat unique peer-ASN list for quick scanning
    all_peers: set[str] = set()
    for key in ("peers_ipv4", "peers_ipv6", "upstreams_ipv4", "upstreams_ipv6",
                "downstreams_ipv4", "downstreams_ipv6"):
        for entry in result.get(key, []):
            all_peers.add(entry["asn"])
    result["connected_asns"] = sorted(all_peers)

    # Summary counts
    result["prefix_count_v4"] = len(result["ipv4_prefixes"])
    result["prefix_count_v6"] = len(result["ipv6_prefixes"])
    result["peer_count"]      = len(result["connected_asns"])

    return result


async def _enrich_ip(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """Look up the BGP route / origin AS for an IP address."""
    url = f"{_BASE}/ip/{ip}"
    resp = await _polite_fetch(client, url)
    if resp is None:
        return {}

    soup = BeautifulSoup(resp.text, "lxml")
    result: dict[str, Any] = {
        "ip": ip,
        "source_url": url,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }

    # Route table — usually a single <table> with prefix/ASN/description columns
    table = soup.find("table")
    if table:
        for tr in table.find_all("tr")[1:]:
            cells = tr.find_all("td")
            if len(cells) >= 3:
                prefix  = cells[0].get_text(strip=True)
                asn_raw = cells[1].get_text(strip=True)
                desc    = cells[2].get_text(strip=True)
                asn_num = _norm_asn(asn_raw)
                if prefix:
                    result.setdefault("routes", []).append({
                        "prefix":      prefix,
                        "origin_asn":  asn_num,
                        "description": desc,
                    })

    # Origin ASN convenience field (first route)
    routes = result.get("routes", [])
    if routes:
        result["origin_asn"] = routes[0].get("origin_asn")
        result["containing_prefix"] = routes[0].get("prefix")

    # --- If we found an origin ASN, also pull its full ASN detail ---
    origin_asn = result.get("origin_asn")
    if origin_asn:
        asn_detail = await _enrich_asn(client, origin_asn)
        if asn_detail:
            result["asn_detail"] = asn_detail

    return result


@register
class BGPHEProvider(BaseEnrichmentProvider):
    name = "bgp_he"
    kind = "asn"
    supported_kinds = {"asn", "ip_address", "ip", "domain"}

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        async with httpx.AsyncClient(timeout=45) as client:
            if entity_kind == "asn":
                asn_num = _norm_asn(entity_value)
                if not asn_num:
                    logger.warning("bgp_he: cannot parse ASN from value", value=entity_value)
                    return {}
                return await _enrich_asn(client, asn_num)

            elif entity_kind in ("ip_address", "ip"):
                return await _enrich_ip(client, entity_value)

            elif entity_kind == "domain":
                # For domains, resolve to IP first is complex; just do a direct
                # HE DNS lookup page which shows origin AS for A/AAAA records.
                url = f"{_BASE}/dns/{entity_value}"
                resp = await _polite_fetch(client, url)
                if resp is None:
                    return {}
                soup = BeautifulSoup(resp.text, "lxml")
                result: dict = {
                    "domain": entity_value,
                    "source_url": url,
                    "scraped_at": datetime.now(timezone.utc).isoformat(),
                }
                table = soup.find("table")
                if table:
                    records = []
                    for tr in table.find_all("tr")[1:]:
                        cells = [td.get_text(strip=True) for td in tr.find_all("td")]
                        if cells:
                            records.append(cells)
                    result["dns_records"] = records[:50]
                return result

        return {}
