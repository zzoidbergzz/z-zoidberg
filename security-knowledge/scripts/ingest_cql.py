#!/usr/bin/env python3
"""Ingest Query-Hub CQL queries + add CQL hunt suggestions to existing entities.

Phase 1: Ingest all 149 CQL queries as detection entities with full YAML
Phase 2: For existing threat actors, malware, CVEs, techniques — suggest relevant CQL hunts
Phase 3: Add CQL language reference + best practices as knowledge entities
"""
import os, re, json, uuid, yaml
import psycopg

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

# ── Phase 1: Ingest CQL Queries ─────────────────────────────────
print("\n=== Phase 1: CQL Query Ingestion ===")
qhub = "/tmp/query-hub/queries"
count = 0
for f in sorted(os.listdir(qhub)):
    if not f.endswith('.yml'): continue
    path = os.path.join(qhub, f)
    try:
        with open(path) as fh:
            raw = fh.read()
        data = yaml.safe_load(raw)
    except:
        continue

    if not isinstance(data, dict): continue
    name = data.get("name", f.replace('.yml',''))
    description = data.get("description", "")
    author = data.get("author", "")
    log_sources = data.get("log_sources", [])
    tags = data.get("tags", [])
    mitre_ids = data.get("mitre_ids", [])
    cql = data.get("cql", "")
    cs_modules = data.get("cs_required_modules", [])

    if not name or not cql: continue

    eid = upsert("detection", f"CQL: {name}", refs={
        "detection_type": "cql", "author": author,
        "log_sources": log_sources, "tags": tags,
        "mitre_ids": mitre_ids if mitre_ids else [],
        "cs_required_modules": cs_modules,
        "source": "Query-Hub (ByteRay)", "trust_tier": 2,
        "file": f,
    })

    add_claim(eid, "detection_detail", {
        "assertion": f"CQL hunt: {name}. {description[:300]}" if description else f"CQL hunt: {name}",
        "cql": cql, "description": description,
        "log_sources": log_sources, "tags": tags,
        "mitre_ids": mitre_ids,
        "detection_type": "cql",
        "tags_search": ["cql", "crowdstrike", "next-gen-siem", "hunt"] + tags + (mitre_ids or []),
    }, conf=0.9)

    # Link to MITRE techniques
    for mid in (mitre_ids or []):
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM entities WHERE mitre_attack_id=%s AND tenant_id=%s LIMIT 1", (mid, TENANT))
            r = cur.fetchone()
            if r:
                add_rel(eid, r[0], "detects", 0.9)

    count += 1
    if count % 30 == 0: print(f"  ... {count}")

print(f"  CQL queries: {count}")

# ── Phase 2: CQL Hunt Suggestions for Existing Entities ─────────
print("\n=== Phase 2: CQL Hunt Suggestions ===")

# Map threat keywords to CQL queries
CQL_HUNTS = {
    # (pattern_in_entity_name_or_kind, CQL suggestion, description)
    "lateral movement": (
        "CQL: Detect Lateral Movement",
        "#event.dataset = falcon.host\n| event.platform = * \n| event.category = NetworkActivity\n| NetworkConnect_... IP NOT IN (internal_subnets)\n| groupby([ComputerName, NetworkConnect_...IP, NetworkConnect_...Port])",
        "Hunt for lateral movement via network connections to unusual IPs"
    ),
    "credential access": (
        "CQL: Credential Dumping Detection",
        "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| ProcessName IN (\"lsass.exe\", \"mimikatz.exe\", \"procdump.exe\")\n| OR CommandLine REGEX \"sekurlsa|logonpasswords|lsadump|procdump.*lsass\"\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine])",
        "Hunt for LSASS access and credential dumping tools"
    ),
    "persistence": (
        "CQL: Registry Run Key Persistence",
        "#event.dataset = falcon.host\n| event.category = RegistryActivity\n| RegistryKeyPath REGEX \"Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run\"\n| table([timestamp, ComputerName, UserName, RegistryKeyPath, RegistryValue])",
        "Hunt for persistence via Run keys and startup entries"
    ),
    "ransomware": (
        "CQL: Ransomware Indicators",
        "#event.dataset = falcon.host\n| event.category = FileActivity\n| (FileName REGEX \"\\\\.(encrypted|locked|crypt|crypto)$\" OR CommandLine REGEX \"vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|shadowcopy.*delete\")\n| table([timestamp, ComputerName, UserName, FileName, CommandLine])",
        "Hunt for ransomware file encryption and volume shadow copy deletion"
    ),
    "cobalt strike": (
        "CQL: Cobalt Strike Beacon Detection",
        "#event.dataset = falcon.host\n| (ProcessName IN (\"cmd.exe\", \"powershell.exe\") AND ParentProcessName IN (\"rundll32.exe\", \"svchost.exe\"))\n| OR CommandLine REGEX \"\\\\.dll,.*Start|beacon|cobaltstrike\"\n| OR NetworkConnect_...Port IN (443, 80, 8080) AND ImageFileName REGEX \"rundll32|svchost\"\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine, ParentProcessName])",
        "Hunt for Cobalt Strike beacon patterns: DLL side-loading, unusual parent-child, suspicious network"
    ),
    "exploit": (
        "CQL: Exploit Attempt Detection",
        "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| (CommandLine REGEX \"-e cmd|powershell.*-enc|certutil.*-urlcache|bitsadmin.*transfer\")\n| OR ProcessName IN (\"mshta.exe\", \"certutil.exe\", \"bitsadmin.exe\", \"wmic.exe\")\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine])",
        "Hunt for LOLBin abuse common in exploit chains"
    ),
    "spearphishing": (
        "CQL: Suspicious Email Attachment Execution",
        "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| ImageFileName REGEX \"AppData|Temp|Downloads\"\n| AND (FileName REGEX \"\\\\.(doc|xls|ppt|pdf|zip|iso|img|vhd)$\")\n| AND ParentProcessName IN (\"outlook.exe\", \"excel.exe\", \"winword.exe\", \"acrobat.exe\")\n| table([timestamp, ComputerName, UserName, ProcessName, ParentProcessName, ImageFileName])",
        "Hunt for macros and attachments spawning processes from email"
    ),
    "privilege escalation": (
        "CQL: Privilege Escalation Indicators",
        "#event.dataset = falcon.host\n| (event.category = ProcessActivity AND UserName REGEX \"SYSTEM|LocalService|NetworkService\")\n| AND ParentProcessName NOT IN (\"services.exe\", \"smss.exe\", \"csrss.exe\", \"wininit.exe\")\n| table([timestamp, ComputerName, UserName, ProcessName, ParentProcessName, CommandLine])",
        "Hunt for SYSTEM processes with unexpected parents"
    ),
    "command and control": (
        "CQL: C2 Beacon Detection via DNS",
        "#event.dataset = falcon.dns\n| DnsRequest_...Name REGEX \"[a-z0-9]{8,}\\.(com|net|org|xyz|top|info)\"\n| OR DnsRequest_...Name NOT IN (top_1m_domains)\n| groupby([ComputerName, DnsRequest_...Name])\n| count > 50\n| table([ComputerName, DnsRequest_...Name, count])",
        "Hunt for DNS beaconing to DGA-like domains"
    ),
    "defense evasion": (
        "CQL: Defense Evasion - Process Hollowing",
        "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| (ProcessName IN (\"svchost.exe\", \"explorer.exe\", \"taskhostw.exe\") AND ImageFileName NOT REGEX \"System32|SysWOW64\")\n| OR (ProcessName = \"svchost.exe\" AND ParentProcessName NOT IN (\"services.exe\", \"msmpeng.exe\"))\n| table([timestamp, ComputerName, UserName, ProcessName, ParentProcessName, ImageFileName])",
        "Hunt for process hollowing and masquerading"
    ),
}

# Add CQL suggestions to existing entities based on their kind/claims
cql_suggest_count = 0
with conn.cursor() as cur:
    cur.execute("SELECT id, kind, canonical_name FROM entities WHERE tenant_id=%s AND kind IN ('attack_pattern','threat_actor','malware','tool','vulnerability')", (TENANT,))
    entities = cur.fetchall()

for eid, kind, name in entities:
    name_lower = name.lower()
    suggested = []

    for pattern, (hunt_name, cql, desc) in CQL_HUNTS.items():
        if pattern in name_lower:
            suggested.append({"hunt": hunt_name, "cql": cql, "description": desc})

    # Also suggest based on kind
    if kind == "attack_pattern" and not suggested:
        # Generic hunt for any technique
        suggested.append({
            "hunt": f"CQL: Hunt for {name}",
            "cql": f"#event.dataset = falcon.host\n| event.category = ProcessActivity\n| CommandLine REGEX \"{name_lower.replace(' ','.*')}\"\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine])",
            "description": f"Generic CQL hunt for indicators related to {name}"
        })

    if suggested:
        add_claim(eid, "detection_detail", {
            "assertion": f"Suggested CQL hunts for {name}: {len(suggested)} queries available for CrowdStrike Next-Gen SIEM.",
            "cql_suggestions": suggested,
            "detection_type": "cql_suggestion",
            "tags": ["cql", "crowdstrike", "hunt-suggestion"],
        }, conf=0.75)
        cql_suggest_count += 1

print(f"  CQL suggestions added to {cql_suggest_count} entities")

# ── Phase 3: CQL Language Reference ─────────────────────────────
print("\n=== Phase 3: CQL Language Reference ===")

cql_ref = [
    ("CQL Syntax Overview", "other", 
     "CrowdStrike Query Language (CQL) is the query language for CrowdStrike Next-Gen SIEM (formerly Humio). "
     "Key syntax: #event.dataset selects log source. Pipe | separates operations. "
     "Comparison: =, !=, REGEX, IN, NOT IN, <, >, <=, >=. "
     "Aggregation: groupby(), count, avg, min, max, percentile. "
     "Renaming: := rename(). Table output: table([field1, field2]). "
     "Time filter: @timestamp >= now(-1h). Wildcard: * matches any value. "
     "Comment: # at start of line. Case-insensitive field matching by default."),
    ("CQL Best Practices", "other",
     "1. Always start with #event.dataset to narrow log source — improves query performance 10-100x. "
     "2. Use = instead of REGEX when possible — exact match is indexed and fast. "
     "3. Add time bounds: @timestamp >= now(-24h) to limit scan range. "
     "4. Use groupby() + count for beaconing/hunting rather than returning all events. "
     "5. Field names are case-insensitive but use underscore notation: ProcessName, ComputerName. "
     "6. Use table([fields]) to control output columns and reduce data transfer. "
     "7. Chain filters with | for readability — each pipe is a stage. "
     "8. Use NOT IN instead of != for exclusion lists. "
     "9. Test queries in live tail first before alerting. "
     "10. Tag queries with MITRE ATT&CK IDs for mapping."),
    ("CQL Log Sources", "other",
     "Common #event.dataset values: falcon.host (endpoint), falcon.cloud (cloud audit), "
     "falcon.dns (DNS queries), falcon.audit (Falcon platform audit), falcon.sensor (sensor health), "
     "falcon.firewall (network firewall), falcon.mobile (mobile). "
     "For custom ingests: aws:cloudtrail, azure:activity, gcp:audit, o365:management, okta:system. "
     "Use #event.dataset = * to search all but this is very slow on large deployments."),
    ("CQL Limitations", "other",
     "1. No JOIN between datasets — CQL is single-stream per query. "
     "2. No subqueries — use materialized views or scheduled queries instead. "
     "3. REGEX is not indexed — avoid on high-volume fields without pre-filtering. "
     "4. Max result size: 10,000 events per query (use groupby/count for larger). "
     "5. No UPDATE/DELETE — CQL is read-only. "
     "6. Field name discovery: use field=* or live tail to discover available fields. "
     "7. Time range limited to retention period of the repository. "
     "8. Cross-repo queries require explicit repo reference: #repo=repoName. "
     "9. Complex nested logic may require temp field assignment via :=. "
     "10. API rate limits apply to scheduled queries and alerts."),
    ("CQL Field Reference - Endpoint", "other",
     "Key fields in #event.dataset = falcon.host: "
     "ComputerName, UserName, ProcessName, ParentProcessName, ImageFileName, CommandLine, "
     "event.category (ProcessActivity, NetworkActivity, FileActivity, RegistryActivity), "
     "NetworkConnect_...IP, NetworkConnect_...Port, NetworkConnect_...Protocol, "
     "FileName, FilePath, RegistryKeyPath, RegistryValue, "
     "SensorId, LocalIP, aid (agent ID), aip (agent IP). "
     "Use field=* in live tail to discover all available fields for a specific event type."),
]

ref_count = 0
for name, kind, desc in cql_ref:
    eid = upsert(kind, name, refs={
        "source": "CrowdStrike CQL Documentation", "trust_tier": 1,
        "topic": "cql", "type": "language_reference",
    })
    add_claim(eid, "concept", {
        "assertion": desc,
        "topic": "cql", "tags": ["cql", "crowdstrike", "query-language", "reference"],
    }, conf=1.0)
    ref_count += 1

print(f"  CQL reference entries: {ref_count}")

conn.close()
print(f"\n✅ CQL ingestion complete: {count} queries, {cql_suggest_count} suggestions, {ref_count} references")
