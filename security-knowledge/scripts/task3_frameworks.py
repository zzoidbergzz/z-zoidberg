#!/usr/bin/env python3
"""Task 3: CWE catalog, CAPEC, MITRE D3FEND, OWASP Top 10, CIS Controls, NIST mappings"""
import psycopg, uuid, json, urllib.request

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

def fetch_json(url, timeout=60):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "zoidberg/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  FETCH {url}: {e}")
        return None

# ── CWE Catalog ─────────────────────────────────────────────────
print("\n=== CWE Catalog ===")
# Fetch CWE full list from MITRE
cwe_data = fetch_json("https://cwe.mitre.org/data/downloads.html")
# The CWE doesn't have a simple JSON API. Use the XML export instead.
# Alternative: use the NVD CWE catalog
cwe_url = "https://services.nvd.nist.gov/rest/json/cwes/2.0?resultsPerPage=2000"
cwe_resp = fetch_json(cwe_url, timeout=60)

cwe_count = 0
if cwe_resp and cwe_resp.get("weaknesses"):
    for w in cwe_resp["weaknesses"]:
        cwe = w.get("cwe", {})
        cwe_id = cwe.get("cweId", "")
        name = cwe.get("name", "")
        desc = ""
        for d in cwe.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("description", "")
                break
        if not cwe_id: continue

        eid = upsert("cwe", cwe_id, refs={
            "cwe_id": cwe_id, "source": "NVD CWE", "trust_tier": 1,
        })
        add_claim(eid, "vulnerability_detail", {
            "assertion": desc[:500] if desc else f"CWE: {cwe_id} - {name}",
            "cwe_id": cwe_id, "name": name, "description": desc[:800] if desc else "",
            "tags": ["cwe", "weakness"],
        }, conf=1.0)
        cwe_count += 1

print(f"  CWE: {cwe_count}")

# ── CAPEC ────────────────────────────────────────────────────────
print("\n=== CAPEC ===")
capec_url = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix2.1/capec-bundle.json"
capec_data = fetch_json(capec_url, timeout=120)
capec_count = 0
if capec_data and capec_data.get("objects"):
    for obj in capec_data["objects"]:
        if obj.get("type") != "attack-pattern": continue
        capec_id = ""
        for er in obj.get("external_references", []):
            if er.get("source_name") == "capec":
                capec_id = er.get("external_id", "")
                break
        if not capec_id: continue

        name = obj.get("name", capec_id)
        desc = obj.get("description", "")
        eid = upsert("attack_pattern", f"CAPEC: {name}", refs={
            "capec_id": capec_id, "stix_id": obj.get("id", ""),
            "source": "MITRE CAPEC", "trust_tier": 1,
        })
        add_claim(eid, "technique_detail", {
            "assertion": desc[:500] if desc else f"CAPEC: {capec_id} - {name}",
            "capec_id": capec_id, "name": name,
            "tags": ["capec", "attack-pattern"],
        }, conf=1.0)
        capec_count += 1
print(f"  CAPEC: {capec_count}")

# ── MITRE D3FEND ────────────────────────────────────────────────
print("\n=== D3FEND ===")
d3fend_url = "https://raw.githubusercontent.com/d3fend/d3fend-ontology/main/d3fend.json"
d3fend_data = fetch_json(d3fend_url, timeout=120)
d3fend_count = 0
if d3fend_data:
    # D3FEND is a large JSON-LD ontology
    # Extract defensive technique classes
    graph = d3fend_data.get("@graph", [])
    for node in graph:
        if not isinstance(node, dict): continue
        ntype = node.get("@type", "")
        if isinstance(ntype, list):
            ntype = ntype[0] if ntype else ""
        if "d3fend" not in str(ntype).lower() and "Technique" not in str(ntype): continue

        name = node.get("rdfs:label", node.get("d3fend:hasDisplayName", ""))
        if not name or not isinstance(name, str): continue
        did = node.get("@id", "")
        desc = node.get("d3fend:definition", node.get("rdfs:comment", ""))
        if isinstance(desc, dict): desc = desc.get("@value", "")
        if not isinstance(desc, str): desc = ""

        eid = upsert("course_of_action", f"D3FEND: {name}", refs={
            "d3fend_id": did, "source": "MITRE D3FEND", "trust_tier": 1,
        })
        add_claim(eid, "technique_detail", {
            "assertion": desc[:500] if desc else f"D3FEND defensive technique: {name}",
            "d3fend_id": did, "tags": ["d3fend", "defense", "course-of-action"],
        }, conf=1.0)
        d3fend_count += 1
        if d3fend_count >= 500: break
print(f"  D3FEND: {d3fend_count}")

# ── OWASP Top 10 (2021) ─────────────────────────────────────────
print("\n=== OWASP Top 10 ===")
owasp = [
    ("A01:2021", "Broken Access Control", "Access control failures allow unauthorized access. Most prevalent web vulnerability. Includes IDOR, privilege escalation, forced browsing, CORS misconfiguration. 94% of applications tested had some form of broken access control."),
    ("A02:2021", "Cryptographic Failures", "Failures related to cryptography: weak algorithms (MD5, SHA1), missing encryption, improper key management, insufficient randomness. Previously 'Sensitive Data Exposure'."),
    ("A03:2021", "Injection", "SQL injection, NoSQL injection, OS command injection, LDAP injection, XSS. 94% of apps tested with some form of injection. Prevent: parameterized queries, input validation, output encoding."),
    ("A04:2021", "Insecure Design", "Missing or ineffective security controls at design level. Threat modeling gaps, missing security requirements, insecure design patterns. New category in 2021."),
    ("A05:2021", "Security Misconfiguration", "Default credentials, open cloud storage, incomplete setup, unnecessary features enabled, verbose errors. 90% of apps tested had some misconfiguration."),
    ("A06:2021", "Vulnerable and Outdated Components", "Known CVEs in dependencies, unsupported software, missing patching. #2 in community survey. Check: OWASP Dependency-Check, Snyk, Dependabot."),
    ("A07:2021", "Identification and Authentication Failures", "Weak passwords, credential stuffing, missing MFA, session fixation. Previously 'Broken Authentication'."),
    ("A08:2021", "Software and Data Integrity Failures", "Insecure CI/CD, unsigned updates, insecure deserialization, unverified CDN. SolarWinds example. New in 2021."),
    ("A09:2021", "Security Logging and Monitoring Failures", "Insufficient logging, missing alerting, no incident response. Enables persistence and data exfiltration without detection."),
    ("A10:2021", "Server-Side Request Forgery", "SSRF allows attackers to reach internal services. Cloud metadata endpoint access (169.254.169.254). New in 2021. High impact in cloud environments."),
]
owasp_count = 0
for code, name, desc in owasp:
    eid = upsert("vulnerability", f"OWASP {code}: {name}", refs={
        "owasp_code": code, "source": "OWASP Top 10 2021", "trust_tier": 1,
    })
    add_claim(eid, "vulnerability_detail", {
        "assertion": f"OWASP Top 10 2021 - {code}: {name}. {desc}",
        "owasp_code": code, "name": name, "description": desc,
        "tags": ["owasp", "web-security", code.lower().replace(":","-")],
    }, conf=1.0)
    owasp_count += 1
print(f"  OWASP: {owasp_count}")

# ── CIS Controls v8 ──────────────────────────────────────────────
print("\n=== CIS Controls v8 ===")
cis = [
    ("1", "Inventory and Control of Enterprise Assets", "Actively manage (inventory, track, and correct) all enterprise assets (end-user devices, network devices, non-computing/ IoT devices, and servers) connected to the infrastructure."),
    ("2", "Inventory and Control of Software Assets", "Actively manage (inventory, track, and correct) all software on the network so that only authorized software is installed and can execute."),
    ("3", "Data Protection", "Develop processes and technical controls to properly classify, securely handle, retain, and dispose of data."),
    ("4", "Secure Configuration of Enterprise Assets and Software", "Establish and maintain the secure configuration of enterprise assets and software."),
    ("5", "Account Management", "Use processes and tools to assign and manage authorization to credentials for user and service accounts."),
    ("6", "Access Control Management", "Use processes and tools to create, assign, manage, and revoke access to enterprise assets and software."),
    ("7", "Continuous Vulnerability Management", "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets, prioritizing remediation."),
    ("8", "Audit Log Management", "Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack."),
    ("9", "Email and Web Browser Protections", "Improve protections and detections of threats from email and web vectors, as these are opportunities for attackers."),
    ("10", "Malware Defenses", "Prevent or control the installation, spread, and execution of malicious applications, code, or scripts."),
    ("11", "Data Recovery", "Establish and maintain data recovery practices to manage backups and restoration of enterprise assets."),
    ("12", "Network Infrastructure Management", "Establish and maintain security controls to protect network architecture and network communications."),
    ("13", "Network Monitoring and Defense", "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense."),
    ("14", "Security Awareness and Skills Training", "Establish and maintain a security awareness program to influence behavior and security culture."),
    ("15", "Service Provider Management", "Develop a process to evaluate service providers who hold sensitive data, or are responsible for an enterprise's critical IT platforms or processes."),
    ("16", "Application Software Security", "Manage the security life cycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses."),
    ("17", "Incident Response Management", "Establish a program to develop and maintain an incident response capability."),
    ("18", "Penetration Testing", "Establish and maintain a penetration testing program appropriate to the size, complexity, and industry of the organization."),
]
cis_count = 0
for num, name, desc in cis:
    eid = upsert("course_of_action", f"CIS Control {num}: {name}", refs={
        "cis_control": num, "source": "CIS Controls v8", "trust_tier": 1,
    })
    add_claim(eid, "framework_detail", {
        "assertion": f"CIS Control {num}: {name}. {desc}",
        "cis_control": num, "name": name, "description": desc,
        "tags": ["cis-controls", "framework", "defense"],
    }, conf=1.0)
    cis_count += 1
print(f"  CIS: {cis_count}")

# ── NIST CSF 2.0 Functions ───────────────────────────────────────
print("\n=== NIST CSF 2.0 ===")
nist = [
    ("GOVERN", "GV", "Organizational context, risk management strategy, supply chain risk management, roles, policy"),
    ("IDENTIFY", "ID", "Asset management, risk assessment, supply chain risk management, improvement"),
    ("PROTECT", "PR", "Access control, awareness training, data security, platform security, technology infrastructure resilience"),
    ("DETECT", "DE", "Continuous monitoring, adverse event analysis, understanding attack surface and attack vectors"),
    ("RESPOND", "RS", "Incident management, analysis, mitigation, reporting, communication"),
    ("RECOVER", "RC", "Recovery plan execution, improvements, communication"),
]
nist_count = 0
for func, code, desc in nist:
    eid = upsert("framework", f"NIST CSF: {func}", refs={
        "nist_csf_function": code, "source": "NIST CSF 2.0", "trust_tier": 1,
    })
    add_claim(eid, "framework_detail", {
        "assertion": f"NIST CSF 2.0 Function {func} ({code}): {desc}",
        "function": func, "code": code, "description": desc,
        "tags": ["nist-csf", "framework", "risk-management"],
    }, conf=1.0)
    nist_count += 1
print(f"  NIST CSF: {nist_count}")

conn.close()
print(f"\n✅ Frameworks and catalogs complete")
