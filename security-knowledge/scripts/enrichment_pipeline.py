#!/usr/bin/env python3
"""Comprehensive enrichment pipeline — direct DB + API hybrid.

Uses PostgreSQL directly for entity upsert (full field control)
and API for claims/relationships where the endpoints exist.
"""
import argparse, json, os, sys, time, urllib.request, uuid
from datetime import UTC, datetime

API = os.environ.get("SK_API", "http://localhost:8010")
API_KEY = os.environ.get("SK_KEY", "YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ")
DB_URL = "postgresql://sk:sk@localhost:5433/sk"
TENANT_UUID = "bcc8ab78-0982-4ea3-81d3-7e4bd166881a"  # from existing entities

import psycopg

def get_db():
    return psycopg.connect(DB_URL, autocommit=True)

TENANT_UUID = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')

def get_db():
    conn = psycopg.connect(DB_URL, autocommit=True)
    conn.execute("SET app.bypass = true")
    return conn
    body = json.dumps(data).encode()
    req = urllib.request.Request(f"{API}{path}", data=body, headers={
        "X-API-Key": API_KEY, "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return None

def fetch_json(url, timeout=60):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "zoidberg-enrichment/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  FETCH {url}: {e}")
        return None

def db_upsert_entity(db, kind, name, refs=None, mitre_id=None):
    """Upsert entity directly into DB, return entity UUID."""
    refs = refs or {}
    with db.cursor() as cur:
        cur.execute("SELECT id FROM entities WHERE canonical_name = %s AND tenant_id = %s", (name, TENANT_UUID))
        row = cur.fetchone()
        if row:
            if refs or mitre_id:
                cur.execute("UPDATE entities SET external_refs = COALESCE(external_refs, '{}') || %s, mitre_attack_id = COALESCE(%s, mitre_attack_id), updated_at = NOW() WHERE id = %s",
                           (json.dumps(refs), mitre_id, row[0]))
            return row[0]
        eid = uuid.uuid4()
        cur.execute("INSERT INTO entities (id, tenant_id, kind, canonical_name, mitre_attack_id, external_refs) VALUES (%s, %s, %s, %s, %s, %s)",
                   (eid, TENANT_UUID, kind, name, mitre_id, json.dumps(refs)))
        return eid

def db_create_claim(db, entity_id, claim_type, value, confidence=0.9, source=""):
    with db.cursor() as cur:
        cid = uuid.uuid4()
        cur.execute("INSERT INTO claims (id, entity_id, tenant_id, claim_type, value, confidence, status, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW()) ON CONFLICT DO NOTHING",
                   (cid, entity_id, TENANT_UUID, claim_type, json.dumps(value), confidence, 'approved'))
        return cid

def db_create_relationship(db, from_id, to_id, kind, confidence=1.0):
    with db.cursor() as cur:
        # Check existing
        cur.execute("SELECT id FROM relationships WHERE from_entity_id = %s AND to_entity_id = %s AND kind = %s AND tenant_id = %s",
                   (from_id, to_id, kind, TENANT_UUID))
        if cur.fetchone():
            return None
        rid = uuid.uuid4()
        cur.execute("INSERT INTO relationships (id, tenant_id, from_entity_id, to_entity_id, kind, confidence) VALUES (%s, %s, %s, %s, %s, %s)",
                   (rid, TENANT_UUID, from_id, to_id, kind, confidence))
        return rid

# ── Phase 1: CISA KEV ───────────────────────────────────────────

def phase_kev():
    print("\n=== Phase 1: CISA KEV ===")
    data = fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if not data: return 0
    vulns = data.get("vulnerabilities", [])
    print(f"  KEV catalog: {len(vulns)} entries")
    db = get_db()
    count = 0
    for v in vulns:
        cve_id = v.get("cveID", "")
        if not cve_id: continue
        eid = db_upsert_entity(db, "cve", cve_id, refs={
            "kev": True, "vendor_project": v.get("vendorProject", ""),
            "product": v.get("product", ""), "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""), "due_date": v.get("dueDate", ""),
            "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse", ""),
            "source": "CISA KEV", "trust_tier": 1,
        })
        db_create_claim(db, eid, "vulnerability_detail", {
            "assertion": f"{cve_id} is in CISA KEV catalog. Product: {v.get('product','')}. Ransomware: {v.get('knownRansomwareCampaignUse','')}",
            "kev_date_added": v.get("dateAdded", ""), "ransomware_use": v.get("knownRansomwareCampaignUse", "") == "Known",
            "tags": ["kev", "cisa", "exploited"],
        }, confidence=1.0, source="CISA KEV Catalog")
        count += 1
        if count % 200 == 0: print(f"  ... {count}/{len(vulns)}")
    db.close()
    print(f"  KEV: {count} CVEs")
    return count

# ── Phase 2: NVD Bulk ───────────────────────────────────────────

def phase_nvd():
    print("\n=== Phase 2: NVD Bulk ===")
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT id, canonical_name FROM entities WHERE kind = 'cve' AND tenant_id = %s LIMIT 200", (TENANT_UUID,))
        cves = cur.fetchall()
    print(f"  {len(cves)} CVEs to enrich")
    count = 0
    for eid, cve_id in cves:
        nvd = fetch_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        if not nvd or not nvd.get("vulnerabilities"): time.sleep(0.6); continue
        vuln = nvd["vulnerabilities"][0].get("cve", {})
        metrics = vuln.get("metrics", {})
        cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
        cwe_ids = []
        for w in vuln.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"): cwe_ids.append(d["value"])
        desc = next((d["value"] for d in vuln.get("descriptions", []) if d.get("lang") == "en"), "")
        db_create_claim(db, eid, "vulnerability_detail", {
            "assertion": desc[:500], "cvss_v31_score": cvss31.get("baseScore"),
            "cvss_v31_vector": cvss31.get("vectorString"), "cvss_v31_severity": cvss31.get("baseSeverity"),
            "cwe_ids": cwe_ids, "tags": ["nvd", "cve"],
        }, confidence=1.0, source=f"NVD {cve_id}")
        for cwe in cwe_ids:
            cwe_eid = db_upsert_entity(db, "cwe", cwe, refs={"source": "NVD", "trust_tier": 1})
            db_create_relationship(db, eid, cwe_eid, "has_weakness", 1.0)
        count += 1
        if count % 20 == 0: print(f"  ... {count}")
        time.sleep(0.6)
    db.close()
    print(f"  NVD: {count} enriched")
    return count

# ── Phase 3: MITRE ATT&CK ───────────────────────────────────────

def phase_mitre():
    print("\n=== Phase 3: MITRE ATT&CK ===")
    data = fetch_json("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", timeout=120)
    if not data: return 0
    objects = data.get("objects", [])
    db = get_db()

    def get_aid(obj):
        for er in obj.get("external_references", []):
            if er.get("source_name") == "mitre-attack": return er.get("external_id", "")
        return ""

    stix_map = {}  # stix_id → entity_id

    # Techniques
    tc = 0
    for t in objects:
        if t.get("type") != "attack-pattern": continue
        aid = get_aid(t)
        if not aid: continue
        tactics = [kc.get("phase_name","") for kc in t.get("kill_chain_phases",[]) if kc.get("kill_chain_name")=="mitre-attack"]
        eid = db_upsert_entity(db, "attack_pattern", t.get("name", aid), refs={
            "mitre_attack_id": aid, "stix_id": t.get("id",""), "tactics": tactics,
            "platforms": t.get("x_mitre_platforms",[]), "data_sources": t.get("x_mitre_data_sources",[]),
            "detection": t.get("x_mitre_detection",""), "is_subtechnique": "." in aid,
            "source": "MITRE ATT&CK", "trust_tier": 1,
        }, mitre_id=aid)
        stix_map[t.get("id","")] = eid
        db_create_claim(db, eid, "technique_detail", {
            "assertion": t.get("description","")[:800], "tactics": tactics,
            "platforms": t.get("x_mitre_platforms",[]), "detection_guidance": t.get("x_mitre_detection",""),
            "tags": ["mitre-attack","technique"] + tactics,
        }, confidence=1.0, source=f"MITRE ATT&CK {aid}")
        tc += 1
    print(f"  Techniques: {tc}")

    # Groups
    gc = 0
    for g in objects:
        if g.get("type") != "intrusion-set": continue
        aid = get_aid(g)
        if not aid: continue
        eid = db_upsert_entity(db, "threat_actor", g.get("name", aid), refs={
            "mitre_attack_id": aid, "stix_id": g.get("id",""),
            "aliases": g.get("aliases",[]), "source": "MITRE ATT&CK", "trust_tier": 1,
        }, mitre_id=aid)
        stix_map[g.get("id","")] = eid
        db_create_claim(db, eid, "actor_profile", {
            "assertion": g.get("description","")[:800], "aliases": g.get("aliases",[]),
            "tags": ["mitre-attack","threat-group"] + g.get("aliases",[])[:5],
        }, confidence=1.0, source=f"MITRE ATT&CK {aid}")
        gc += 1
    print(f"  Groups: {gc}")

    # Software
    sc = 0
    for s in objects:
        if s.get("type") not in ("malware", "tool"): continue
        aid = get_aid(s)
        if not aid: continue
        st = s.get("type","malware")
        eid = db_upsert_entity(db, st, s.get("name", aid), refs={
            "mitre_attack_id": aid, "stix_id": s.get("id",""),
            "platforms": s.get("x_mitre_platforms",[]), "source": "MITRE ATT&CK", "trust_tier": 1,
        }, mitre_id=aid)
        stix_map[s.get("id","")] = eid
        db_create_claim(db, eid, "tool_capability" if st=="tool" else "malware_detail", {
            "assertion": s.get("description","")[:800], "platforms": s.get("x_mitre_platforms",[]),
            "tags": ["mitre-attack", st],
        }, confidence=1.0, source=f"MITRE ATT&CK {aid}")
        sc += 1
    print(f"  Software: {sc}")

    # Relationships
    rc = 0
    for sr in objects:
        if sr.get("type") != "relationship": continue
        src = stix_map.get(sr.get("source_ref",""))
        tgt = stix_map.get(sr.get("target_ref",""))
        if src and tgt:
            db_create_relationship(db, src, tgt, sr.get("relationship_type","related-to"), 0.9)
            rc += 1
        if rc % 1000 == 0: print(f"  ... {rc} rels")
    print(f"  Relationships: {rc}")
    db.close()
    return tc + gc + sc

# ── Phase 4: MISP Galaxies ──────────────────────────────────────

def phase_misp():
    print("\n=== Phase 4: MISP Galaxies ===")
    db = get_db()
    galaxies = [
        ("threat-actor", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"),
        ("malware", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malware.json"),
        ("tool", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tool.json"),
        ("banker", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/banker.json"),
        ("rat", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/rat.json"),
        ("stealer", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/stealer.json"),
        ("botnet", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/botnet.json"),
        ("ransomware", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json"),
    ]
    total = 0
    for kind, url in galaxies:
        data = fetch_json(url)
        if not data: continue
        clusters = data.get("values", [])
        print(f"  {kind}: {len(clusters)} clusters")
        c = 0
        for cl in clusters[:500]:
            name = cl.get("value","")
            if not name: continue
            meta = cl.get("meta",{})
            # Map MISP kind to EntityKind
            ek = {"threat-actor":"threat_actor", "banker":"malware", "rat":"malware",
                  "stealer":"malware", "botnet":"malware", "ransomware":"malware"}.get(kind, kind)
            eid = db_upsert_entity(db, ek, name, refs={
                "misp_galaxy": data.get("name",kind), "misp_uuid": cl.get("uuid",""),
                "synonyms": meta.get("synonyms",[])[:10], "refs": meta.get("refs",[])[:5],
                "source": "MISP Galaxy", "trust_tier": 2,
            })
            db_create_claim(db, eid, "actor_profile" if "actor" in kind else "malware_detail" if ek=="malware" else "tool_capability", {
                "assertion": cl.get("description","")[:500], "synonyms": meta.get("synonyms",[])[:10],
                "tags": ["misp-galaxy", kind] + meta.get("synonyms",[])[:3],
            }, confidence=0.85, source=f"MISP Galaxy: {data.get('name',kind)}")
            c += 1
        total += c
        print(f"  {kind}: {c}")
    db.close()
    print(f"  MISP total: {total}")
    return total

# ── Phase 5: Sigma ──────────────────────────────────────────────

def phase_sigma():
    print("\n=== Phase 5: Sigma ===")
    sigma_path = "/tmp/sigma"
    if not os.path.exists(sigma_path):
        os.system("git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma 2>/dev/null")
    rules_dir = os.path.join(sigma_path, "rules")
    if not os.path.exists(rules_dir): print("  No rules dir"); return 0
    db = get_db()
    count = 0
    for root, dirs, files in os.walk(rules_dir):
        for f in files:
            if not f.endswith((".yml",".yaml")): continue
            path = os.path.join(root, f)
            try: content = open(path).read()
            except: continue
            title = ""; attack_ids = []
            for line in content.split("\n"):
                if line.startswith("title:"): title = line.split(":",1)[1].strip().strip("'\"")
                if line.strip().startswith("- "):
                    val = line.strip()[2:].strip()
                    if val.startswith("T1") and len(val) >= 6:
                        attack_ids.append(val.split(".")[0] if "." in val else val)
            if not title or not attack_ids: continue
            eid = db_upsert_entity(db, "detection", f"Sigma: {title}", refs={
                "detection_type": "sigma", "attack_ids": attack_ids,
                "source": "SigmaHQ", "trust_tier": 2,
            })
            db_create_claim(db, eid, "detection_detail", {
                "assertion": f"Sigma: {title}. Techniques: {', '.join(attack_ids)}",
                "rule_content": content[:4000], "detection_type": "sigma", "attack_ids": attack_ids,
                "tags": ["sigma","detection"] + attack_ids[:5],
            }, confidence=0.9, source="SigmaHQ")
            count += 1
            if count % 200 == 0: print(f"  ... {count}")
    db.close()
    print(f"  Sigma: {count}")
    return count

# ── Phase 6: Atomic Red Team ────────────────────────────────────

def phase_atomic():
    print("\n=== Phase 6: Atomic Red Team ===")
    db = get_db()
    url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/atomics/atomic-red-team-index.md"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "zoidberg/1.0"})
        content = urllib.request.urlopen(req, timeout=30).read().decode()
    except: print("  Failed"); return 0
    count = 0
    for line in content.split("\n"):
        line = line.strip()
        if not line.startswith("- T1"): continue
        parts = line[2:].split(" ", 1)
        if len(parts) < 2: continue
        aid = parts[0].split(".")[0]
        name = parts[1]
        eid = db_upsert_entity(db, "technique", f"ART: {name}", refs={
            "atomic_red_team_id": parts[0], "mitre_attack_id": aid,
            "source": "Atomic Red Team", "trust_tier": 2,
        }, mitre_id=aid)
        db_create_claim(db, eid, "technique_detail", {
            "assertion": f"Atomic Red Team test for {name} ({parts[0]}).",
            "test_type": "atomic_red_team", "tags": ["atomic-red-team","emulation"],
        }, confidence=0.9, source="Atomic Red Team")
        count += 1
    db.close()
    print(f"  ART: {count}")
    return count

# ── Phase 7: EPSS ───────────────────────────────────────────────

def phase_epss():
    print("\n=== Phase 7: EPSS ===")
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT id, canonical_name FROM entities WHERE kind = 'cve' AND tenant_id = %s LIMIT 200", (TENANT_UUID,))
        cves = cur.fetchall()
    print(f"  {len(cves)} CVEs")
    count = 0
    for eid, cve_id in cves:
        data = fetch_json(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        if not data or not data.get("data"): time.sleep(0.5); continue
        epss = data["data"][0]
        db_create_claim(db, eid, "vulnerability_detail", {
            "assertion": f"EPSS: {float(epss.get('epss',0)):.5f} p{float(epss.get('percentile',0)):.3f}",
            "epss_score": float(epss.get("epss",0)), "epss_percentile": float(epss.get("percentile",0)),
            "tags": ["epss"],
        }, confidence=1.0, source="FIRST EPSS API")
        count += 1; time.sleep(0.5)
    db.close()
    print(f"  EPSS: {count}")
    return count

# ── Phase 8: Breach Reports ─────────────────────────────────────

def phase_breach():
    print("\n=== Phase 8: Breach Reports ===")
    db = get_db()
    reports = [
        ("DFIR: BazarLoader→Cobalt Strike", "https://thedfirreport.com/2020/11/30/bazarloader-to-cobalt-strike/",
         ["BazarLoader","Cobalt Strike"], ["T1059.001","T1055","T1021.001"], "2020-11-30"),
        ("DFIR: Ryuk's Return", "https://thedfirreport.com/2021/02/01/ryuks-return/",
         ["Ryuk","TrickBot"], ["T1486","T1059.001"], "2021-02-01"),
        ("DFIR: IcedID→Cobalt Strike", "https://thedfirreport.com/2021/11/29/icedid-to-cobalt-strike/",
         ["IcedID"], ["T1059.001","T1053.005"], "2021-11-29"),
        ("DFIR: BlackBasta", "https://thedfirreport.com/2022/06/06/bazarloader-and-blackbasta-ransomware/",
         ["BlackBasta"], ["T1486","T1059.001","T1055"], "2022-06-06"),
        ("DFIR: Qakbot→BlackBasta", "https://thedfirreport.com/2023/09/19/qakbot-to-blackbasta-in-1-hour/",
         ["QakBot","BlackBasta"], ["T1059.001","T1486"], "2023-09-19"),
        ("Mandiant M-Trends 2024", "https://www.mandiant.com/resources/blog/m-trends-2024",
         ["APT29","APT41"], ["T1566.001","T1059.001"], "2024-04"),
        ("MS DART: Volt Typhoon", "https://www.microsoft.com/en-us/security/blog/2024/05/28/volt-typhoon-targets-us-critical-infrastructure/",
         ["Volt Typhoon"], ["T1078","T1059.001"], "2024-05-28"),
        ("Volexity: Ivanti 0-day", "https://www.volexity.com/blog/2024/01/10/active-exploitation-of-ivanti-connect-secure-vpn/",
         ["UNC5221"], ["T1190","T1059.004"], "2024-01-10"),
        ("CrowdStrike: Scattered Spider", "https://www.crowdstrike.com/blog/scattered-spider-uses-social-engineering-and-living-off-the-land-techniques/",
         ["Scattered Spider"], ["T1078","T1110"], "2023-11"),
        ("Unit42: CL0P", "https://unit42.paloaltonetworks.com/clop-ransomware/",
         ["CL0P","TA505"], ["T1486","T1190"], "2023-06"),
        ("Securelist: Fin7", "https://securelist.com/fin7-2-0-attack-techniques/111269/",
         ["FIN7","Carbanak"], ["T1566.001","T1059.001"], "2022"),
        ("CISA: Volt Typhoon AA23-136", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a",
         ["Volt Typhoon"], ["T1078","T1059.001"], "2023-05-24"),
    ]
    count = 0
    for title, url, actors, techniques, date in reports:
        eid = db_upsert_entity(db, "report", title, refs={
            "url": url, "date": date, "actors_mentioned": actors,
            "techniques_covered": techniques, "source_type": "breach_report", "trust_tier": 2,
        })
        db_create_claim(db, eid, "report_detail", {
            "assertion": f"Breach: {title}. Actors: {', '.join(actors)}. Techniques: {', '.join(techniques)}",
            "actors": actors, "techniques": techniques, "tags": ["breach-report","dfir"] + actors[:3],
        }, confidence=0.85, source=url)
        count += 1
    db.close()
    print(f"  Breach: {count}")
    return count

# ── Phase 9: Relationships ──────────────────────────────────────

def phase_relationships():
    print("\n=== Phase 9: Relationship Builder ===")
    db = get_db()
    with db.cursor() as cur:
        cur.execute("SELECT id, kind, mitre_attack_id, external_refs FROM entities WHERE tenant_id = %s", (TENANT_UUID,))
        entities = cur.fetchall()
    by_mitre = {}
    for eid, kind, mid, refs in entities:
        if mid: by_mitre.setdefault(mid, []).append(eid)
    print(f"  {len(entities)} entities, {len(by_mitre)} MITRE IDs")
    rc = 0
    for mid, eids in by_mitre.items():
        for i, e1 in enumerate(eids):
            for e2 in eids[i+1:]:
                db_create_relationship(db, e1, e2, "shares_technique", 0.8)
                rc += 1
    db.close()
    print(f"  Relationships: {rc}")
    return rc

# ── Phase 10: Sysinternals ──────────────────────────────────────

def phase_sysinternals():
    print("\n=== Phase 10: Sysinternals ===")
    db = get_db()
    tools = [
        ("Sysmon", "tool", "T1059", "System Monitor - advanced Windows event logging. Captures process creation, network connections, file creation time changes, registry changes, DNS queries, image loads. Essential for detection engineering. Event IDs 1-255."),
        ("ProcMon", "tool", "T1057", "Process Monitor - real-time file system, registry, process/thread activity monitor. 12M events/sec. Used for malware behavioral analysis and system baselining."),
        ("Autoruns", "tool", "T1547", "Enumerates all auto-starting code locations. 30+ autostart locations. Critical for persistence discovery during IR."),
        ("PsExec", "tool", "T1021.002", "Remote process execution via SMB/named pipes. Creates PSEXESVC temporary service. Commonly abused for lateral movement."),
        ("Process Explorer", "tool", "T1057", "Advanced task manager. Process trees, DLL handles, TCP/UDP endpoints, token privileges, verified signatures."),
        ("TCPView", "tool", "T1071", "Real-time TCP/UDP endpoint viewer. Useful for detecting C2 beaconing."),
        ("Strings", "tool", None, "Scans files for ASCII/Unicode strings. Essential for malware triage and IOC extraction."),
        ("Sigcheck", "tool", None, "File signature verification. Reports certificate chain, signing time, revocation status. Key for trust validation."),
    ]
    count = 0
    for name, kind, mid, desc in tools:
        eid = db_upsert_entity(db, kind, name, refs={"sysinternals": True, "source": "Microsoft Sysinternals", "trust_tier": 1}, mitre_id=mid)
        db_create_claim(db, eid, "tool_capability", {
            "assertion": desc[:800], "tool_category": "sysinternals",
            "download_url": f"https://learn.microsoft.com/en-us/sysinternals/downloads/{name.lower()}",
            "tags": ["sysinternals","windows","forensics","detection"],
        }, confidence=1.0, source="Microsoft Sysinternals Documentation")
        count += 1
    db.close()
    print(f"  Sysinternals: {count}")
    return count

PHASES = {
    "kev": phase_kev, "nvd": phase_nvd, "mitre": phase_mitre,
    "misp": phase_misp, "sigma": phase_sigma, "atomic": phase_atomic,
    "epss": phase_epss, "breach": phase_breach, "relationships": phase_relationships,
    "sysinternals": phase_sysinternals,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=list(PHASES.keys()) + ["all"])
    args = parser.parse_args()
    if args.phase == "all":
        for name, fn in PHASES.items():
            try: fn()
            except Exception as e: print(f"  Phase {name} error: {e}")
    else:
        PHASES[args.phase]()
    print("\n✅ Done")


def update_search_vectors():
    """Regenerate tsvector search indices for all entities."""
    print("\n=== Search Vector Rebuild ===")
    db = get_db()
    with db.cursor() as cur:
        cur.execute("UPDATE entities SET search_vector = to_tsvector('english', COALESCE(canonical_name, '') || ' ' || COALESCE(mitre_attack_id, '')) WHERE search_vector IS NULL")
        print(f"  Updated {cur.rowcount} entity vectors")
        cur.execute("UPDATE claims SET search_vector = to_tsvector('english', COALESCE(value::text, '')) WHERE search_vector IS NULL")
        print(f"  Updated {cur.rowcount} claim vectors")
    db.close()
