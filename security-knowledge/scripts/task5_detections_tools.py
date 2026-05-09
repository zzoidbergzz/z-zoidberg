#!/usr/bin/env python3
"""Task 5: Elastic detection rules + MITRE ATT&CK mitigations + Sysmon configs + Offensive tooling"""
import psycopg, uuid, json, os, urllib.request

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

# ── Elastic Detection Rules ─────────────────────────────────────
print("\n=== Elastic Detection Rules ===")
elastic_path = "/tmp/elastic-rules"
if not os.path.exists(elastic_path):
    os.system("git clone --depth 1 https://github.com/elastic/detection-rules.git /tmp/elastic-rules 2>/dev/null")

count = 0
rules_dir = os.path.join(elastic_path, "rules")
if os.path.exists(rules_dir):
    for root, dirs, files in os.walk(rules_dir):
        for f in files:
            if not f.endswith(".toml"): continue
            path = os.path.join(root, f)
            try: content = open(path).read()
            except: continue

            title = ""; attack_ids = []; rule_type = ""; risk_score = ""
            in_threat = False
            for line in content.split("\n"):
                if line.startswith("rule_name ="): title = line.split("=",1)[1].strip().strip('"')
                if line.startswith("type ="): rule_type = line.split("=",1)[1].strip().strip('"')
                if line.startswith("risk_score ="): risk_score = line.split("=",1)[1].strip().strip('"')
                if "[threat]" in line.lower() or "threat.framework" in line.lower(): in_threat = True; continue
                if in_threat and line.strip().startswith("threat.technique.id"):
                    val = line.split("=",1)[1].strip().strip('"')
                    if val.startswith("T"): attack_ids.append(val)
                if in_threat and line.strip() == "" and attack_ids: in_threat = False

            if not title or not attack_ids: continue

            eid = upsert("detection", f"Elastic: {title}", refs={
                "detection_type": "elastic", "attack_ids": list(set(attack_ids)),
                "rule_type": rule_type, "risk_score": risk_score,
                "source": "Elastic Detection Rules", "trust_tier": 2,
            })
            add_claim(eid, "detection_detail", {
                "assertion": f"Elastic rule: {title}. Techniques: {', '.join(set(attack_ids))}",
                "rule_content": content[:4000], "detection_type": "elastic",
                "attack_ids": list(set(attack_ids)), "risk_score": risk_score,
                "tags": ["elastic", "detection"] + list(set(attack_ids))[:5],
            }, conf=0.9)
            count += 1
            if count % 200 == 0: print(f"  ... {count}")

print(f"  Elastic: {count} rules")

# ── MITRE ATT&CK Mitigations ────────────────────────────────────
print("\n=== MITRE Mitigations ===")
data = None
try:
    req = urllib.request.Request("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", headers={"User-Agent":"zoidberg/1.0"})
    data = json.loads(urllib.request.urlopen(req, timeout=120).read())
except: pass

mit_count = 0
if data:
    for obj in data.get("objects", []):
        if obj.get("type") != "course-of-action": continue
        name = obj.get("name", "")
        desc = obj.get("description", "")
        aid = ""
        for er in obj.get("external_references", []):
            if er.get("source_name") == "mitre-attack": aid = er.get("external_id",""); break
        if not name: continue
        eid = upsert("course_of_action", f"Mitigation: {name}", refs={
            "mitre_attack_id": aid, "source": "MITRE ATT&CK", "trust_tier": 1,
        }, mitre_id=aid or None)
        add_claim(eid, "technique_detail", {
            "assertion": desc[:500] if desc else f"MITRE mitigation: {name}",
            "mitre_id": aid, "tags": ["mitre-attack", "mitigation", "course-of-action"],
        }, conf=1.0)
        mit_count += 1
print(f"  Mitigations: {mit_count}")

# ── Sysmon Configs ──────────────────────────────────────────────
print("\n=== Sysmon Configs ===")
sysmon_configs = [
    ("SwiftOnSecurity sysmon-config", "https://github.com/SwiftOnSecurity/sysmon-config", "Popular Sysmon configuration with comprehensive event logging. Tracks process creation, network connections, image loads, file creation, registry changes. Used as baseline for many enterprise deployments."),
    ("olafhartong sysmon-modular", "https://github.com/olafhartong/sysmon-modular", "Modular Sysmon configuration with individual file-based rule management. Easier to maintain and customize. Includes threat hunting focused event collection."),
    ("sysmonconfig.xml (SwiftOnSecurity)", "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig.xml", "The actual XML configuration file. Logs: ProcessCreate (EID 1), FileCreateTime (EID 2), NetworkConnect (EID 3), ProcessTerminate (EID 5), DriverLoad (EID 6), ImageLoad (EID 7), CreateRemoteThread (EID 8), RawAccessRead (EID 9), ProcessAccess (EID 10), FileCreate (EID 11), RegistryAddDelete (EID 12), RegistrySet (EID 13), RegistryRename (EID 14), FileCreateStreamHash (EID 15), PipeEvent (EID 17), WmiEvent (EID 19), DnsQuery (EID 22), FileDelete (EID 23), ClipboardChange (EID 24), ProcessTampering (EID 25), FileDeleteDetected (EID 26)"),
]
sc_count = 0
for name, url, desc in sysmon_configs:
    eid = upsert("tool", f"Sysmon Config: {name}", refs={
        "url": url, "config_type": "sysmon", "source": "GitHub", "trust_tier": 2,
    })
    add_claim(eid, "tool_capability", {
        "assertion": desc, "url": url, "config_type": "sysmon",
        "tags": ["sysmon", "configuration", "detection", "windows"],
    }, conf=0.9)
    sc_count += 1
print(f"  Sysmon configs: {sc_count}")

# ── Offensive Tooling Catalogue ─────────────────────────────────
print("\n=== Offensive Tooling ===")
offensive_tools = [
    ("Metasploit Framework", "tool", "T1059", "Comprehensive penetration testing framework. 2,000+ exploit modules, 1,000+ auxiliary modules, 500+ payloads. Primary post-exploitation tool. MSFvenom payload generation, Meterpreter interactive shell, Railgun for Windows API calls."),
    ("Cobalt Strike", "tool", "T1059", "Commercial adversary simulation platform. Beacon C2 with Malleable C2 profiles, SMB/TCP/HTTP/DNS channels, lateral movement via PSExec/WMI/DCOM, token manipulation, screenshot/keylog, privilege escalation. Most abused red team tool by APTs."),
    ("BloodHound", "tool", "T1087.002", "Active Directory graph analysis tool. Maps attack paths via ACLs, group memberships, sessions, trust relationships. SharpHound collector gathers AD data. Used by both red and blue teams. Critical for AD security assessment."),
    ("CrackMapExec (NetExec)", "tool", "T1021", "Post-exploitation Swiss army knife for AD networks. SMB/WinRM/LDAP/MSSQL/SSH execution. Credential testing, command execution, LAPS dumping, GPP decryption. Now maintained as NetExec."),
    ("Mimikatz", "tool", "T1003.001", "Windows credential extraction tool. Extracts plaintext passwords, Kerberos tickets, NTLM hashes from LSASS. sekurlsa::logonpasswords, kerberos::ptt (pass-the-ticket), lsadump::dcsync. Most credential theft tool in incident response."),
    ("Responder", "tool", "T1557.001", "LLMNR/NBT-NS/MDNS poisoner. Captures NTLMv1/v2 hashes via name resolution poisoning. WPAD proxy injection. Essential for internal pentesting. Runs on any network interface."),
    ("Impacket", "tool", "T1021.002", "Python class library for network protocol interaction. psexec.py, wmiexec.py, secretsdump.py (DCSync alternative), GetNPUsers.py (AS-REP roast), GetUserSPNs.py (Kerberoasting). Core AD offensive toolkit."),
    ("Rubeus", "tool", "T1558", "C# Kerberos attack toolkit. Kerberoasting, AS-REP roasting, pass-the-ticket, pass-the-key, S4U2Self/S4U2Proxy abuse, diamond ticket, golden ticket. Primary Kerberos attack tool."),
    ("SharpHound", "tool", "T1087.002", "BloodHound data collector. Gathers AD objects, ACLs, group memberships, GPOs, OU structure, trust relationships. Output imported into BloodHound for attack path analysis."),
    ("Nuclei", "tool", "T1190", "Fast vulnerability scanner using YAML templates. 5,000+ community templates covering CVEs, misconfigurations, exposed panels. Used for both bug bounty and internal scanning. Interactsh integration for OOB testing."),
]

ot_count = 0
for name, kind, mitre, desc in offensive_tools:
    eid = upsert(kind, name, refs={
        "offensive_tool": True, "source": "Security Community", "trust_tier": 2,
    }, mitre_id=mitre)
    add_claim(eid, "tool_capability", {
        "assertion": desc[:800],
        "tags": ["offensive-security", "red-team", "penetration-testing", kind],
    }, conf=0.85)
    ot_count += 1
print(f"  Offensive tools: {ot_count}")

conn.close()
print(f"\n✅ Task 5 complete")
