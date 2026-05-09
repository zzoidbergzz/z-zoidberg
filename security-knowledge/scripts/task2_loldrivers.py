#!/usr/bin/env python3
"""Task 2: LoLDrivers full YAML source + CVE/SIGMA/Elastic deep enrichment"""
import psycopg, uuid, json, os, urllib.request, yaml

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

def upsert(kind, name, refs=None, mitre_id=None):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM entities WHERE canonical_name=%s AND tenant_id=%s", (name, TENANT))
        r = cur.fetchone()
        if r:
            if refs or mitre_id:
                cur.execute("UPDATE entities SET external_refs=COALESCE(external_refs,'{}')||%s, mitre_attack_id=COALESCE(%s,mitre_attack_id), updated_at=NOW() WHERE id=%s", (json.dumps(refs or {}), mitre_id, r[0]))
            return r[0]
        eid = uuid.uuid4()
        cur.execute("INSERT INTO entities (id,tenant_id,kind,canonical_name,mitre_attack_id,external_refs,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,NOW(),NOW())", (eid,TENANT,kind,name,mitre_id,json.dumps(refs or {})))
        return eid

def add_claim(eid, ctype, val, conf=0.9):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO claims (id,entity_id,tenant_id,claim_type,value,confidence,status,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,'approved',NOW(),NOW()) ON CONFLICT DO NOTHING", (uuid.uuid4(),eid,TENANT,ctype,json.dumps(val),conf))

def add_rel(f, t, k, c=1.0):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s", (f,t,k,TENANT))
        if cur.fetchone(): return
        cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)", (uuid.uuid4(),TENANT,f,t,k,c))

# Clone LoLDrivers repo
repo_path = "/tmp/loldrivers"
if not os.path.exists(repo_path):
    os.system("git clone --depth 1 https://github.com/magicsword-io/LOLDrivers.git /tmp/loldrivers 2>/dev/null")

# Find all driver YAML files
driver_files = []
for root, dirs, files in os.walk(os.path.join(repo_path, "drivers")):
    for f in files:
        if f.endswith(('.yml', '.yaml')):
            driver_files.append(os.path.join(root, f))

print(f"Found {len(driver_files)} driver YAML files")

count = 0
for path in driver_files:
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
    except:
        continue

    if not isinstance(data, dict):
        continue

    name = data.get("Name", os.path.basename(path).replace('.yml',''))
    category = data.get("Category", "")
    description = data.get("Description", "")
    commands = data.get("Commands", [])
    mitre_id = data.get("MitreID", "")
    detections = data.get("Detection", [])
    tags = data.get("Tags", [])
    author = data.get("Author", "")
    created = data.get("Created", "")
    acknowledged = data.get("Acknowledgement", "")

    eid = upsert("driver", name, refs={
        "loldrivers_id": data.get("Id", ""),
        "category": category, "description": description[:300] if description else "",
        "mitre_attack_id": mitre_id, "author": author, "created": created,
        "tags": tags, "source": "LoLDrivers YAML", "trust_tier": 1,
        "acknowledgement": acknowledged[:200] if acknowledged else "",
    }, mitre_id=mitre_id or None)

    # Build comprehensive claim
    assertion = f"LoLDriver: {name}. Category: {category}."
    if description: assertion += f" {description[:400]}"
    if mitre_id: assertion += f" MITRE: {mitre_id}."

    claim_val = {
        "assertion": assertion, "category": category, "description": description,
        "mitre_id": mitre_id, "tags": tags,
        "commands": commands[:10] if isinstance(commands, list) else [],
        "detection": detections[:5] if isinstance(detections, list) else [],
        "tags_search": ["loldrivers", "vulnerable-driver", category] + tags[:3],
    }

    # Add samples
    samples = data.get("KnownVulnerableSamples", [])
    sample_hashes = []
    for s in samples[:15]:
        sha256 = s.get("SHA256", "")
        md5 = s.get("MD5", "")
        sha1 = s.get("SHA1", "")
        filename = s.get("Filename", "")
        cert = s.get("Certificate", "")
        sig = s.get("Authentihash", "")
        date = s.get("Date", "")

        if sha256:
            hash_eid = upsert("hash", sha256, refs={
                "sha256": sha256, "md5": md5, "sha1": sha1,
                "filename": filename, "certificate": cert, "authentihash": sig,
                "first_seen": date, "vulnerable_driver": name,
                "source": "LoLDrivers YAML", "trust_tier": 1,
            })
            add_claim(hash_eid, "malware_detail", {
                "assertion": f"Vulnerable driver sample: {filename} ({name}). Certificate: {cert}.",
                "sha256": sha256, "filename": filename, "tags": ["loldrivers","vulnerable-driver"],
            }, conf=1.0)
            add_rel(hash_eid, eid, "vulnerable_sample_of", 1.0)
            sample_hashes.append({"sha256":sha256,"md5":md5,"filename":filename})

    claim_val["samples"] = sample_hashes
    add_claim(eid, "tool_capability" if category == "malicious" else "vulnerability_detail", claim_val, conf=1.0)

    # Link to MITRE technique if available
    if mitre_id:
        tech_eid = upsert("attack_pattern", mitre_id, refs={"source": "LoLDrivers", "trust_tier": 1}, mitre_id=mitre_id)
        add_rel(eid, tech_eid, "maps_to_technique", 0.9)

    count += 1
    if count % 200 == 0: print(f"  ... {count}/{len(driver_files)}")

conn.close()
print(f"\n✅ {count} drivers from full YAML source")
