#!/usr/bin/env python3
"""Bulk export all data from z.je Security Knowledge API.

No timeouts — reads everything and saves to JSON files.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

API = "https://z.je"
KEY = "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ"
OUT = "/home/openclaw/.openclaw/workspace/repos/z-zoidberg/data-export"
os.makedirs(OUT, exist_ok=True)


def api_get(path, timeout=120):
    """GET with X-API-Key, return parsed JSON. No timeout on retries."""
    url = f"{API}{path}"
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"X-API-Key": KEY})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 2 ** attempt
                print(f"  Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            if e.code == 404:
                return None
            print(f"  HTTP {e.code} on {path}")
            return None
        except Exception as e:
            wait = 2 ** attempt
            print(f"  Error on {path}: {e}, retrying in {wait}s...")
            time.sleep(wait)
    print(f"  FAILED after 5 attempts: {path}")
    return None


def api_post(path, body, timeout=300):
    """POST with X-API-Key, return parsed JSON."""
    url = f"{API}{path}"
    data = json.dumps(body).encode()
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, data=data, headers={
                "X-API-Key": KEY,
                "Content-Type": "application/json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 2 ** attempt
                print(f"  Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            if e.code == 404:
                return None
            print(f"  HTTP {e.code} on {path}")
            return None
        except Exception as e:
            wait = 2 ** attempt
            print(f"  Error on {path}: {e}, retrying in {wait}s...")
            time.sleep(wait)
    print(f"  FAILED after 5 attempts: {path}")
    return None


def save(name, data):
    path = os.path.join(OUT, f"{name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    count = len(data) if isinstance(data, list) else 1
    print(f"  Saved {path} ({count} records)")


def mcp_call(tool, args=None, timeout=300):
    return api_post("/api/v1/mcp/call", {"tool": tool, "args": args or {}}, timeout=timeout)


def main():
    print("=== Exporting z.je data via API ===\n")

    # 1. Entities (paginate)
    print("--- Entities ---")
    all_entities = []
    offset = 0
    limit = 200
    while True:
        batch = api_get(f"/api/v1/entities/?limit={limit}&offset={offset}")
        if not batch or not isinstance(batch, list) or len(batch) == 0:
            break
        all_entities.extend(batch)
        print(f"  Got {len(batch)} entities (total: {len(all_entities)})")
        if len(batch) < limit:
            break
        offset += limit
    save("entities", all_entities)

    # 2. Claims
    print("--- Claims ---")
    all_claims = []
    offset = 0
    while True:
        batch = api_get(f"/api/v1/claims/?limit={limit}&offset={offset}")
        if not batch or not isinstance(batch, list) or len(batch) == 0:
            break
        all_claims.extend(batch)
        print(f"  Got {len(batch)} claims (total: {len(all_claims)})")
        if len(batch) < limit:
            break
        offset += limit
    save("claims", all_claims)

    # 3. Evidence
    print("--- Evidence ---")
    all_evidence = []
    offset = 0
    while True:
        batch = api_get(f"/api/v1/evidence/?limit={limit}&offset={offset}")
        if not batch or not isinstance(batch, list) or len(batch) == 0:
            break
        all_evidence.extend(batch)
        print(f"  Got {len(batch)} evidence (total: {len(all_evidence)})")
        if len(batch) < limit:
            break
        offset += limit
    save("evidence", all_evidence)

    # 4. Sources
    print("--- Sources ---")
    sources = mcp_call("list_sources")
    if sources:
        save("sources", sources if isinstance(sources, list) else [sources])

    # 5. Feed status
    print("--- Feed Status ---")
    feed = mcp_call("feed_status")
    if feed:
        save("feed_status", feed if isinstance(feed, list) else [feed])

    # 6. MITRE ATT&CK data
    print("--- MITRE ATT&CK ---")
    for tool in ["get_all_techniques", "get_all_groups", "get_all_software",
                 "get_all_mitigations", "get_all_tactics", "get_all_campaigns"]:
        print(f"  {tool}...")
        data = mcp_call(tool, timeout=600)
        if data:
            save(f"mitre_{tool}", data if isinstance(data, list) else [data])

    # 7. Entity details (with enrichment data)
    print("--- Entity Details ---")
    detailed = []
    for i, ent in enumerate(all_entities):
        eid = ent.get("id")
        if not eid:
            continue
        detail = api_get(f"/api/v1/entities/{eid}")
        if detail:
            detailed.append(detail)
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(all_entities)} entities detailed")
    save("entity_details", detailed)

    # 8. Search index (common queries for corpus data)
    print("--- Search Results ---")
    search_terms = ["CVE-2024", "CVE-2025", "malware", "ransomware", "APT",
                    "supply chain", "zero-day", "exploit", "phishing", "backdoor"]
    search_results = {}
    for term in search_terms:
        print(f"  Searching: {term}")
        results = api_get(f"/api/v1/search/?q={term}&limit=100")
        if results:
            search_results[term] = results
    save("search_results", search_results)

    # 9. Audit log
    print("--- Audit Log ---")
    audit = api_get("/api/v1/audit/?limit=500")
    if audit:
        save("audit", audit if isinstance(audit, list) else [audit])

    # 10. Detections
    print("--- Detections ---")
    dets = mcp_call("list_detections")
    if dets:
        save("detections", dets if isinstance(dets, list) else [dets])

    # 11. Corpus search
    print("--- Corpus ---")
    corpus = mcp_call("corpus_search", {"query": "", "limit": 500})
    if corpus:
        save("corpus", corpus if isinstance(corpus, list) else [corpus])

    # 12. OpenAPI spec
    print("--- OpenAPI Spec ---")
    spec = api_get("/openapi.json")
    if spec:
        save("openapi", spec)

    print(f"\n=== Export complete. Files in {OUT} ===")
    for f in sorted(os.listdir(OUT)):
        size = os.path.getsize(os.path.join(OUT, f))
        print(f"  {f}: {size:,} bytes")


if __name__ == "__main__":
    main()
