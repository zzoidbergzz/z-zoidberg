#!/usr/bin/env python3
"""Import LOLDrivers dataset into Security Knowledge DB.

Each YAML entry becomes a 'driver' entity with claims for
hashes, MITRE mapping, detection, and known samples.
"""
import json, os, sys, urllib.request, yaml

API = "http://localhost:8010"
KEY = os.environ.get("SK_API_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")
LOLDRIVERS_DIR = "/home/openclaw/.openclaw/workspace/repos/LOLDrivers/yaml"

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

def main():
    print("=== LOLDrivers Import ===")
    yamls = [f for f in os.listdir(LOLDRIVERS_DIR) if f.endswith('.yaml')]
    print(f"Found {len(yamls)} driver entries")

    imported = 0
    malicious = 0
    vulnerable = 0

    for i, fname in enumerate(yamls):
        fpath = os.path.join(LOLDRIVERS_DIR, fname)
        with open(fpath) as f:
            try: entry = yaml.safe_load(f)
            except: continue

        if not entry: continue

        lold_id = entry.get('Id', fname.replace('.yaml', ''))
        category = entry.get('Category', 'unknown')
        mitre_id = entry.get('MitreID', '')
        tags = entry.get('Tags', [])
        author = entry.get('Author', '')
        created = entry.get('Created', '')
        verified = entry.get('Verified', 'FALSE')

        # Get first known sample for naming
        samples = entry.get('KnownVulnerableSamples', [])
        sample_info = samples[0] if samples else {}

        # Create entity name from tags or filename
        driver_name = tags[0] if tags else sample_info.get('OriginalFilename', lold_id[:16])
        entity_name = f"LOLDriver:{driver_name}"

        eid = create_entity(entity_name, "driver")
        if not eid:
            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{len(yamls)}] (skip: {entity_name})")
            continue

        # Category claim
        if category == 'malicious':
            malicious += 1
        else:
            vulnerable += 1

        add_claim(eid, "capability", {
            "text": f"LOLDriver entry ({category}). {'Verified' if verified == 'TRUE' else 'Unverified'}. MITRE: {mitre_id}. {', '.join(entry.get('Commands', [{}])[0].get('Description', '') if isinstance(entry.get('Commands'), list) and len(entry.get('Commands', [])) > 0 else '') if entry.get('Commands') else ''}",
            "category": category,
            "verified": verified == 'TRUE',
            "loldriver_id": lold_id,
            "created": created,
        }, 1.0 if verified == 'TRUE' else 0.7)

        # MITRE mapping
        if mitre_id:
            add_claim(eid, "technique", {
                "text": f"MITRE ATT&CK technique: {mitre_id}. Used for privilege elevation via vulnerable kernel driver.",
                "mitre_attack_id": mitre_id,
            }, 0.9)

        # Hashes from samples
        hashes = []
        for s in samples[:5]:
            h = {}
            if s.get('SHA256'): h['sha256'] = s.get('SHA256', '')
            if s.get('MD5'): h['md5'] = s.get('MD5', '')
            if s.get('SHA1'): h['sha1'] = s.get('SHA1', '')
            if s.get('Imphash'): h['imphash'] = s.get('Imphash', '')
            if s.get('Authentihash', {}).get('SHA256'): h['authentihash_sha256'] = s['Authentihash']['SHA256']
            if s.get('OriginalFilename'): h['original_filename'] = s['OriginalFilename']
            if s.get('Company'): h['company'] = s['Company']
            if s.get('Product'): h['product'] = s['Product']
            if s.get('Description'): h['description'] = s['Description']
            if s.get('Publisher'): h['publisher'] = s['Publisher']
            if s.get('MachineType'): h['machine_type'] = s['MachineType']
            if h: hashes.append(h)

        if hashes:
            add_claim(eid, "ioc", {
                "text": f"Known sample hashes: {len(hashes)} samples. SHA256: {', '.join(h.get('sha256','')[:16]+'...' for h in hashes[:3])}",
                "hashes": hashes,
                "type": "driver_sample_hashes",
            }, 1.0)

        # Detection
        detections = entry.get('Detection', [])
        if detections:
            add_claim(eid, "detection", {
                "text": f"Detection guidance: {json.dumps(detections)[:500]}",
                "detection_rules": detections,
            }, 0.8)

        # Resources
        resources = entry.get('Resources', [])
        if resources:
            add_claim(eid, "evidence", {
                "text": f"Sources: {len(resources)} references",
                "links": resources[:10],
            }, 1.0)

        imported += 1
        if (i + 1) % 100 == 0:
            print(f"  [{i+1}/{len(yamls)}] imported={imported} mal={malicious} vuln={vulnerable}")

    print(f"\nTotal: {imported} drivers imported ({malicious} malicious, {vulnerable} vulnerable)")

if __name__ == "__main__":
    main()
