#!/usr/bin/env python3
"""Ingest local files: ~/briefing.md, ~/ingest/*, and z.je/static/knowledge.md.

Parses each file, extracts entities (CVEs, techniques, IOCs, concepts),
creates entities + claims, links to existing knowledge.
"""
import os, re, json, uuid, urllib.request
import psycopg

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

def upsert(kind, name, refs=None, mitre_id=None):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM entities WHERE canonical_name=%s AND tenant_id=%s", (name, TENANT))
        r = cur.fetchone()
        if r:
            if refs: cur.execute("UPDATE entities SET external_refs=COALESCE(external_refs,'{}')||%s, updated_at=NOW() WHERE id=%s", (json.dumps(refs), r[0]))
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

def extract_iocs(text):
    """Extract CVEs, MITRE techniques, IPs, hashes, domains, emails, crypto addresses."""
    cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))
    techniques = list(set(re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', text)))
    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    sha256 = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)))
    sha1 = list(set(re.findall(r'\b[a-fA-F0-9]{40}\b', text)))
    md5 = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text)))
    emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)))
    btc = list(set(re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', text)))
    # Onion addresses
    onions = list(set(re.findall(r'[a-z2-7]{16,56}\.onion', text)))
    # C2 domains (broad)
    domains = list(set(re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}(?:\.[a-z]{2,})?\b', text)))
    domains = [d for d in domains if d not in ('example.com','localhost','github.com') and not d.endswith('.onion')]
    
    return {
        "cves": cves, "techniques": techniques, "ips": ips[:20],
        "sha256": sha256[:10], "sha1": sha1[:10], "md5": md5[:10],
        "emails": emails[:10], "btc": btc[:10], "onions": onions[:10],
        "domains": domains[:20],
    }

def ingest_file(filepath, source_name):
    """Ingest a single file into the knowledge base."""
    try:
        with open(filepath) as f:
            content = f.read()
    except:
        print(f"  SKIP: {filepath}")
        return 0

    if not content.strip():
        return 0

    iocs = extract_iocs(content)
    
    # Create a report entity for the file
    name = os.path.basename(filepath)
    eid = upsert("report", f"Source: {source_name}/{name}", refs={
        "source": source_name, "file": name,
        "trust_tier": 2,
        "cves": iocs["cves"][:10],
        "techniques": iocs["techniques"][:10],
        "onions": iocs["onions"],
    })

    add_claim(eid, "report_detail", {
        "assertion": f"Ingested from {source_name}/{name}. CVEs: {', '.join(iocs['cves'][:5]) or 'none'}. Techniques: {', '.join(iocs['techniques'][:5]) or 'none'}. Onions: {', '.join(iocs['onions'][:3]) or 'none'}.",
        "full_content": content[:5000],
        "iocs": iocs,
        "tags": [source_name, "ingested"],
    }, conf=0.85)

    # Create IOC entities and link
    for cve in iocs["cves"]:
        cve_eid = upsert("cve", cve, refs={"source": source_name, "trust_tier": 2})
        add_rel(eid, cve_eid, "mentions", 0.85)
    
    for tech in iocs["techniques"]:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM entities WHERE mitre_attack_id=%s AND tenant_id=%s LIMIT 1", (tech, TENANT))
            r = cur.fetchone()
            if r: add_rel(eid, r[0], "references_technique", 0.85)

    for ip in iocs["ips"]:
        ip_eid = upsert("ip_address", ip, refs={"source": source_name, "trust_tier": 2})
        add_rel(eid, ip_eid, "mentions", 0.85)
    
    for h in iocs["sha256"]:
        h_eid = upsert("hash", h, refs={"source": source_name, "trust_tier": 2})
        add_rel(eid, h_eid, "mentions", 0.85)

    for email in iocs["emails"]:
        e_eid = upsert("email", email, refs={"source": source_name, "trust_tier": 2})
        add_rel(eid, e_eid, "mentions", 0.85)

    for btc_addr in iocs["btc"]:
        b_eid = upsert("other", f"BTC: {btc_addr}", refs={"source": source_name, "trust_tier": 2, "crypto_type": "bitcoin"})
        add_rel(eid, b_eid, "mentions", 0.85)

    for onion in iocs["onions"]:
        o_eid = upsert("url", onion, refs={"source": source_name, "trust_tier": 2, "onion": True})
        add_rel(eid, o_eid, "mentions", 0.85)

    return 1

# ── Ingest ~/briefing.md ────────────────────────────────────────
print("=== ~/briefing.md ===")
count = ingest_file(os.path.expanduser("~/briefing.md"), "briefing")
print(f"  Ingested: {count}")

# ── Ingest ~/ingest/* ───────────────────────────────────────────
print("\n=== ~/ingest/ ===")
ingest_dir = os.path.expanduser("~/ingest")
total = 0
if os.path.isdir(ingest_dir):
    for f in sorted(os.listdir(ingest_dir)):
        fp = os.path.join(ingest_dir, f)
        if os.path.isfile(fp):
            c = ingest_file(fp, "ingest")
            total += c
            print(f"  {f}: {'OK' if c else 'SKIP'}")
print(f"  Total: {total}")

# ── Ingest z.je/static/knowledge.md ─────────────────────────────
print("\n=== z.je/static/knowledge.md ===")
try:
    req = urllib.request.Request("https://z.je/static/knowledge.md", headers={"User-Agent":"zoidberg/1.0"})
    km_content = urllib.request.urlopen(req, timeout=30).read().decode()
    # Write to temp and ingest
    km_path = "/tmp/knowledge.md"
    with open(km_path, "w") as f:
        f.write(km_content)
    c = ingest_file(km_path, "knowledge-md")
    print(f"  Lines: {len(km_content.splitlines())}, Ingested: {c}")
    
    # Parse knowledge.md as a QA checklist — each heading is a topic to verify
    topics = []
    for line in km_content.splitlines():
        if line.startswith("#"):
            topic = line.lstrip("#").strip()
            if topic and len(topic) > 3:
                topics.append(topic)
    
    print(f"  Topics (QA checklist): {len(topics)}")
    
    # Create checklist entity
    cl_eid = upsert("report", "Knowledge QA Checklist", refs={
        "source": "z.je/static/knowledge.md", "trust_tier": 1,
        "total_topics": len(topics),
    })
    add_claim(cl_eid, "report_detail", {
        "assertion": f"Knowledge QA checklist with {len(topics)} topics from z.je/static/knowledge.md. Each topic should have expert-level coverage.",
        "topics": topics[:100],
        "tags": ["qa-checklist", "knowledge-topics"],
    }, conf=1.0)
    
    # Check which topics already have knowledge
    with conn.cursor() as cur:
        cur.execute("SELECT canonical_name, kind FROM entities WHERE tenant_id=%s", (TENANT,))
        existing = {r[0].lower(): r[1] for r in cur.fetchall()}
    
    covered = 0
    missing = []
    for topic in topics:
        # Check if any entity matches this topic
        topic_lower = topic.lower()
        if any(topic_lower in name for name in existing):
            covered += 1
        else:
            missing.append(topic)
    
    print(f"  Covered: {covered}/{len(topics)}, Missing: {len(missing)}")
    if missing[:10]:
        print(f"  Sample missing: {missing[:10]}")
    
except Exception as e:
    print(f"  Error: {e}")

conn.close()
print(f"\n✅ File ingestion complete")
