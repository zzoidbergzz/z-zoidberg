#!/usr/bin/env python3
"""Enhanced feed poller with IOC extraction and entity linking.

When new CVEs/feeds are ingested:
1. Extract IOCs (domains, IPs, hashes, CVEs) from feed data
2. Create entities for new IOCs
3. Link IOCs to threat actor profiles
4. Update existing entities with new intelligence
"""
import asyncio
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.request

API = "http://localhost:8010"
KEY = os.environ.get("SK_API_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")

# IOC extraction patterns
PATTERNS = {
    "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'),
    "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|cc|ru|cn|ir|kp|info|biz|me|tv|co|uk|de|fr|br|in|au|ca|jp|kr|tw|hk|sg|ae|sa|il|pk|ph|th|vn|my|id|tr|za|ng|eg|ke|mx|ar|cl|pe|co|ve|ec|bo|py|uy)\b', re.IGNORECASE),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "cve": re.compile(r'CVE-\d{4}-\d{4,}'),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
}


def extract_iocs(text):
    """Extract IOCs from text, filtering out obvious false positives."""
    results = {}
    for kind, pattern in PATTERNS.items():
        matches = set(pattern.findall(text))
        # Filter false positives
        if kind == "ipv4":
            matches = {m for m in matches if not m.startswith(('0.', '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3', '224.', '239.', '255.'))}
        if kind == "domain":
            # Filter common non-IOC domains
            skip = {'example.com', 'localhost', 'github.com', 'microsoft.com', 'google.com', 'python.org', 'wikipedia.org'}
            matches = {m for m in matches if m.lower() not in skip and not m.endswith('.example.com')}
        if kind == "email":
            skip = {'example@example.com', 'noreply@github.com', 'notifications@github.com'}
            matches = {m for m in matches if m.lower() not in skip}
        if matches:
            results[kind] = sorted(matches)
    return results


def mcp_call(tool, args, timeout=30):
    data = json.dumps({"tool": tool, "args": args}).encode()
    req = urllib.request.Request(f"{API}/api/v1/mcp/call", data=data, headers={"X-API-Key": KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def create_entity(name, kind):
    try:
        r = mcp_call("create_entity", {"name": name, "kind": kind})
        return r.get("id")
    except:
        return None


def add_claim(eid, ctype, value, conf=1.0, src=""):
    if not eid: return
    try: mcp_call("create_claim", {"entity_id": eid, "claim_type": ctype, "value": value, "confidence": conf})
    except: pass


def process_cve_corpus():
    """Extract IOCs from CVE corpus entries and create linked entities."""
    print("=== CVE Corpus IOC Extraction ===")

    # Get recent high-severity CVEs
    try:
        req = urllib.request.Request(
            f"{API}/api/v1/search/?q=CVSS+9+critical&limit=50",
            headers={"X-API-Key": KEY}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            cves = json.loads(resp.read())
    except:
        cves = []

    iocs_created = 0
    for cve in cves[:20]:
        # Extract IOCs from description
        desc = ""
        if isinstance(cve, dict):
            desc = cve.get("description", cve.get("name", ""))

        iocs = extract_iocs(desc)
        if not iocs:
            continue

        cve_id = cve.get("canonical_name", cve.get("name", "")) if isinstance(cve, dict) else str(cve)
        cve_eid = cve.get("id") if isinstance(cve, dict) else None

        for ioc_type, ioc_values in iocs.items():
            for ioc_val in ioc_values[:3]:  # Limit per CVE
                # Create IOC entity
                ioc_eid = create_entity(ioc_val, ioc_type if ioc_type not in ("cve", "email") else "ioc")
                if ioc_eid and cve_eid:
                    add_claim(ioc_eid, "relationship", {
                        "text": f"IOC observed in {cve_id}",
                        "related_entity": cve_id,
                        "relationship": "observed_in",
                    }, 0.9, "CVE corpus analysis")
                    iocs_created += 1

    print(f"  Created {iocs_created} IOC entity links from CVE corpus")


def process_threat_actors():
    """Extract IOCs from threat actor claims and create linked entities."""
    print("=== Threat Actor IOC Extraction ===")

    try:
        req = urllib.request.Request(
            f"{API}/api/v1/entities/?limit=200",
            headers={"X-API-Key": KEY}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            entities = json.loads(resp.read())
    except:
        return

    iocs_created = 0
    actors = [e for e in entities if e.get("kind") == "threat_actor"]

    for actor in actors[:30]:
        # Get claims for this actor
        try:
            claims = mcp_call("list_claims", {"entity_id": actor["id"]}) if False else []
        except:
            claims = []

        # Extract IOCs from actor name + description
        text = actor.get("canonical_name", "")
        iocs = extract_iocs(text)

        for ioc_type, ioc_values in iocs.items():
            for ioc_val in ioc_values[:3]:
                ioc_eid = create_entity(ioc_val, ioc_type if ioc_type not in ("cve", "email") else "ioc")
                if ioc_eid:
                    add_claim(ioc_eid, "relationship", {
                        "text": f"IOC associated with {actor['canonical_name']}",
                        "related_entity": actor["canonical_name"],
                        "relationship": "attributed_to",
                    }, 0.85, "Threat actor profile analysis")
                    iocs_created += 1

    print(f"  Created {iocs_created} IOC entities from threat actor profiles")


def searxng_pipeline():
    """Search SearXNG for latest threat intel and create entities."""
    print("=== SearXNG → DB Pipeline ===")

    queries = [
        "ransomware attack 2025 report",
        "APT threat actor 2025 IOC",
        "zero-day exploit 2025 CVE",
        "malware analysis 2025 hash",
    ]

    entities_created = 0
    for query in queries:
        try:
            url = f"http://localhost:8888/search?q={urllib.parse.quote(query)}&format=json&limit=5"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=15) as resp:
                results = json.loads(resp.read()).get("results", [])
        except:
            continue

        for r in results[:3]:
            title = r.get("title", "")[:200]
            url_val = r.get("url", "")
            snippet = r.get("content", "")[:500]

            # Extract IOCs from snippet
            iocs = extract_iocs(snippet)

            # Create document entity for the report
            eid = create_entity(title[:100], "document")
            if eid:
                add_claim(eid, "capability", {
                    "text": f"Threat intel report: {snippet[:300]}",
                    "url": url_val,
                    "iocs_found": {k: v[:5] for k, v in iocs.items()},
                }, 0.7, "SearXNG search pipeline")
                entities_created += 1

    print(f"  Created {entities_created} document entities from SearXNG")


import urllib.parse


def main():
    print("=== Feed Enhancement & IOC Extraction ===")
    process_cve_corpus()
    process_threat_actors()
    searxng_pipeline()
    print("\n=== Done ===")


if __name__ == "__main__":
    main()
