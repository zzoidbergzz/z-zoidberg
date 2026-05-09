#!/usr/bin/env python3
"""Import MISP galaxy clusters as threat actor/malware/tool entities.

MISP galaxies provide curated, structured threat intel data with
aliases, descriptions, and MITRE mappings.
"""
import json, os, urllib.request

API = "http://localhost:8010"
KEY = os.environ.get("SK_API_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")

GALAXY_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/"

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

def add_claim(eid, ctype, value, conf=1.0):
    if not eid: return
    try: mcp_call("create_claim", {"entity_id": eid, "claim_type": ctype, "value": value, "confidence": conf})
    except: pass

def fetch_galaxy(name):
    """Fetch a MISP galaxy cluster JSON."""
    url = f"{GALAXY_URL}{name}.json"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except:
        return None

def import_threat_actor_galaxy():
    """Import MISP Threat Actor galaxy."""
    print("\n=== MISP Threat Actor Galaxy ===")
    galaxy = fetch_galaxy("threat-actor")
    if not galaxy:
        print("  Could not fetch threat-actor galaxy")
        return 0

    imported = 0
    values = galaxy.get('values', [])
    print(f"  Found {len(values)} threat actors in MISP galaxy")

    for actor in values[:100]:  # Limit to 100
        name = actor.get('value', '')
        if not name: continue

        eid = create_entity(f"MISP:{name}", "threat_actor")
        if not eid: continue

        # Description
        desc = actor.get('description', '')
        meta = actor.get('meta', {})

        add_claim(eid, "attribution", {
            "text": f"MISP Galaxy threat actor. {desc[:300]}",
            "country": meta.get('country', []),
            "refs": meta.get('refs', [])[:5],
            "synonyms": meta.get('synonyms', [])[:10],
            "attribution_confidence": meta.get('attribution-confidence', ''),
            "cfr-type-of-incident": meta.get('cfr-type-of-incident', []),
            "cfr-target-of-activity": meta.get('cfr-target-of-activity', []),
        }, 0.85)

        # APT tags
        apt = meta.get('apt-group', [])
        if apt:
            add_claim(eid, "technique", {
                "text": f"APT classification: {', '.join(apt[:5])}",
                "apt_groups": apt[:5],
            }, 0.8)

        imported += 1
        if imported % 25 == 0:
            print(f"  [{imported} imported]")

    print(f"  Imported {imported} threat actors from MISP galaxy")
    return imported

def import_malware_galaxy():
    """Import MISP Tool/Malware galaxy."""
    print("\n=== MISP Tool Galaxy ===")
    galaxy = fetch_galaxy("tool")
    if not galaxy:
        print("  Could not fetch tool galaxy")
        return 0

    imported = 0
    for tool in galaxy.get('values', [])[:100]:
        name = tool.get('value', '')
        if not name: continue

        eid = create_entity(f"MISP-Tool:{name}", "tool")
        if not eid: continue

        desc = tool.get('description', '')
        meta = tool.get('meta', {})

        add_claim(eid, "capability", {
            "text": f"MISP Galaxy tool. {desc[:300]}",
            "refs": meta.get('refs', [])[:5],
            "synonyms": meta.get('synonyms', [])[:5],
        }, 0.9)

        imported += 1

    print(f"  Imported {imported} tools from MISP galaxy")
    return imported

def import_ransomware_galaxy():
    """Import MISP Ransomware galaxy."""
    print("\n=== MISP Ransomware Galaxy ===")
    galaxy = fetch_galaxy("ransomware")
    if not galaxy:
        print("  Could not fetch ransomware galaxy")
        return 0

    imported = 0
    for rw in galaxy.get('values', []):
        name = rw.get('value', '')
        if not name: continue

        eid = create_entity(f"MISP-RW:{name}", "malware")
        if not eid: continue

        desc = rw.get('description', '')
        meta = rw.get('meta', {})

        add_claim(eid, "capability", {
            "text": f"Ransomware family. {desc[:300]}",
            "encryption": meta.get('encryption', ''),
            "extensions": meta.get('extensions', ''),
            "ransomnotes": meta.get('ransomnotes', [])[:2],
            "refs": meta.get('refs', [])[:5],
            "synonyms": meta.get('synonyms', [])[:5],
        }, 0.9)

        imported += 1

    print(f"  Imported {imported} ransomware families from MISP galaxy")
    return imported

def main():
    print("=== MISP Galaxy Import ===")
    total = 0
    total += import_threat_actor_galaxy()
    total += import_malware_galaxy()
    total += import_ransomware_galaxy()
    print(f"\nTotal: {total} entities from MISP galaxies")

if __name__ == "__main__":
    main()
