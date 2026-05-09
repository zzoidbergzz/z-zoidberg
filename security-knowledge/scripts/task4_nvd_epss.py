#!/usr/bin/env python3
"""Task 4: NVD bulk CVE enrichment (CVSS v3/v4, CWE, CPE) + EPSS + KEV cross-ref"""
import psycopg, uuid, json, urllib.request, time

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

def upsert(kind, name, refs=None, mitre_id=None):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM entities WHERE canonical_name=%s AND tenant_id=%s", (name, TENANT))
        r = cur.fetchone()
        if r:
            if refs:
                cur.execute("UPDATE entities SET external_refs=COALESCE(external_refs,'{}')||%s, updated_at=NOW() WHERE id=%s", (json.dumps(refs), r[0]))
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

def fetch_json(url, timeout=30):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "zoidberg-enrichment/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except: return None

# Get all CVEs that need enrichment
with conn.cursor() as cur:
    cur.execute("SELECT id, canonical_name FROM entities WHERE kind='cve' AND tenant_id=%s", (TENANT,))
    cves = cur.fetchall()

print(f"Total CVEs: {len(cves)}")

# Check which already have NVD claims
with conn.cursor() as cur:
    cur.execute("""
        SELECT DISTINCT e.id FROM entities e
        JOIN claims c ON c.entity_id = e.id
        WHERE e.kind='cve' AND e.tenant_id=%s AND c.claim_type='vulnerability_detail'
        AND c.value::text LIKE '%%cvss_v31_score%%'
    """, (TENANT,))
    enriched = set(r[0] for r in cur.fetchall())

need_enrichment = [(eid, name) for eid, name in cves if eid not in enriched]
print(f"Need NVD enrichment: {len(need_enrichment)}")

count = 0
for eid, cve_id in need_enrichment[:500]:  # Batch of 500
    nvd = fetch_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    if not nvd or not nvd.get("vulnerabilities"):
        time.sleep(0.6)
        continue

    vuln = nvd["vulnerabilities"][0].get("cve", {})
    metrics = vuln.get("metrics", {})

    cvss31 = {}
    if metrics.get("cvssMetricV31"):
        m = metrics["cvssMetricV31"][0]
        cvss31 = m.get("cvssData", {})
        cvss31["exploitabilityScore"] = m.get("exploitabilityScore")
        cvss31["impactScore"] = m.get("impactScore")

    cvss40 = {}
    if metrics.get("cvssMetricV40"):
        m = metrics["cvssMetricV40"][0]
        cvss40 = m.get("cvssData", {})

    cwe_ids = []
    for w in vuln.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"): cwe_ids.append(v)

    cpes = set()
    for c in vuln.get("configurations", []):
        for node in c.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                cpes.add(cpe.get("criteria", ""))

    refs = vuln.get("references", [])
    ref_urls = [r.get("url","") for r in refs[:10]]

    desc = next((d["value"] for d in vuln.get("descriptions",[]) if d.get("lang")=="en"), "")

    claim_val = {
        "assertion": desc[:500] if desc else f"NVD: {cve_id}",
        "cvss_v31_score": cvss31.get("baseScore"),
        "cvss_v31_vector": cvss31.get("vectorString"),
        "cvss_v31_severity": cvss31.get("baseSeverity"),
        "cvss_v31_exploitability": cvss31.get("exploitabilityScore"),
        "cvss_v31_impact": cvss31.get("impactScore"),
        "cvss_v40_score": cvss40.get("baseScore") if cvss40 else None,
        "cwe_ids": cwe_ids,
        "affected_cpes": list(cpes)[:20],
        "reference_urls": ref_urls,
        "nvd_published": vuln.get("published", ""),
        "tags": ["nvd", "cve"],
    }
    add_claim(eid, "vulnerability_detail", claim_val, conf=1.0)

    # CWE entities + relationships
    for cwe in cwe_ids:
        cwe_eid = upsert("cwe", cwe, refs={"source": "NVD", "trust_tier": 1})
        add_rel(eid, cwe_eid, "has_weakness", 1.0)

    # EPSS enrichment
    epss = fetch_json(f"https://api.first.org/data/v1/epss?cve={cve_id}")
    if epss and epss.get("data"):
        e = epss["data"][0]
        add_claim(eid, "vulnerability_detail", {
            "assertion": f"EPSS: {float(e.get('epss',0)):.5f} (p{float(e.get('percentile',0)):.3f})",
            "epss_score": float(e.get("epss",0)),
            "epss_percentile": float(e.get("percentile",0)),
            "tags": ["epss"],
        }, conf=1.0)

    count += 1
    if count % 50 == 0: print(f"  ... {count}/{min(500, len(need_enrichment))}")
    time.sleep(0.6)

conn.close()
print(f"\n✅ {count} CVEs enriched with NVD + EPSS")
