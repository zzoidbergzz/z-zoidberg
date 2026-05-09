#!/usr/bin/env python3
"""Import CISA KEV and GitHub Security Advisories into SK DB.

CISA KEV: Known Exploited Vulnerabilities with due dates
GHSA: GitHub Security Advisories for open-source vulnerabilities
"""
import json, os, urllib.request

API = "http://localhost:8010"
KEY = os.environ.get("SK_API_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")

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

def import_cisa_kev():
    """Import CISA Known Exploited Vulnerabilities catalog."""
    print("\n=== CISA KEV Catalog ===")
    try:
        req = urllib.request.Request("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except:
        print("  Could not fetch CISA KEV catalog")
        return 0

    vulns = data.get('vulnerabilities', [])
    print(f"  Found {len(vulns)} KEV entries")

    imported = 0
    for v in vulns[:500]:  # Process up to 500
        cve = v.get('cveID', '')
        if not cve: continue

        eid = create_entity(f"KEV:{cve}", "vulnerability")
        if not eid: continue

        add_claim(eid, "vulnerability", {
            "text": f"Known Exploited Vulnerability. {v.get('shortDescription', '')}. Vendor: {v.get('vendorProject', '')}. Product: {v.get('product', '')}. Required action: {v.get('requiredAction', '')}. Due date: {v.get('dueDate', '')}. Date added: {v.get('dateAdded', '')}.",
            "cve_id": cve,
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "required_action": v.get("requiredAction", ""),
            "due_date": v.get("dueDate", ""),
            "date_added": v.get("dateAdded", ""),
            "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse", ""),
        }, 1.0)

        if v.get('knownRansomwareCampaignUse', '').lower() == 'known':
            add_claim(eid, "relationship", {
                "text": f"KEV entry {cve} is known to be used in ransomware campaigns",
                "related_entity": "ransomware",
                "relationship": "exploited_by",
            }, 0.95)

        imported += 1
        if imported % 100 == 0:
            print(f"  [{imported} imported]")

    print(f"  Imported {imported} CISA KEV entries")
    return imported

def import_ghsa():
    """Import GitHub Security Advisories via API."""
    print("\n=== GitHub Security Advisories ===")
    try:
        req = urllib.request.Request("https://api.github.com/advisories?per_page=100&type=reviewed&severity=critical")
        req.add_header("Accept", "application/vnd.github+json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            advisories = json.loads(resp.read())
    except:
        print("  Could not fetch GHSA advisories")
        return 0

    print(f"  Found {len(advisories)} critical advisories")

    imported = 0
    for adv in advisories[:50]:
        ghsa_id = adv.get('ghsa_id', '')
        if not ghsa_id: continue

        cve = adv.get('cve_id', ghsa_id)
        summary = adv.get('summary', '')

        eid = create_entity(f"GHSA:{ghsa_id}", "vulnerability")
        if not eid: continue

        add_claim(eid, "vulnerability", {
            "text": f"GitHub Security Advisory. {summary}. Severity: {adv.get('severity', '')}. CVSS: {adv.get('cvss', {}).get('score', 'N/A')}. Published: {adv.get('published_at', '')}.",
            "ghsa_id": ghsa_id,
            "cve_id": cve,
            "severity": adv.get("severity", ""),
            "cvss_score": adv.get("cvss", {}).get("score", 0),
            "published_at": adv.get("published_at", ""),
            "references": [r.get("url", "") for r in adv.get("references", [])[:3]],
        }, 0.9)

        # Affected packages
        vulns = adv.get('vulnerabilities', [])
        if vulns:
            packages = [v.get('package', {}).get('name', '') for v in vulns[:5]]
            add_claim(eid, "infrastructure", {
                "text": f"Affects packages: {', '.join(p for p in packages if p)}",
                "affected_packages": packages,
            }, 1.0)

        imported += 1

    print(f"  Imported {imported} GHSA advisories")
    return imported

def main():
    print("=== Advisory Feed Import ===")
    total = 0
    total += import_cisa_kev()
    total += import_ghsa()
    print(f"\nTotal: {total} advisory entities imported")

if __name__ == "__main__":
    main()
