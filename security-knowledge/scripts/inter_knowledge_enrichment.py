#!/usr/bin/env python3
"""Inter-knowledge enrichment: cross-pollinate CQL context, process trees, IOCs
between related entities. No external API calls — purely DB-internal.

For each entity, based on its kind/claims/tags:
1. Generate CQL hunt suggestions with process tree context
2. Build relationships to related entities (same technique, shared tooling)
3. Add contextual "investigation guide" claims linking detection→technique→actor
"""
import psycopg, uuid, json, re

TENANT = uuid.UUID('bcc8ab78-0982-4ea3-81d3-7e4bd166881a')
conn = psycopg.connect('postgresql://sk:sk@localhost:5433/sk', autocommit=True)
conn.execute('SET app.bypass = true')

def add_claim(eid, ctype, val, conf=0.9):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO claims (id,entity_id,tenant_id,claim_type,value,confidence,status,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,'approved',NOW(),NOW()) ON CONFLICT DO NOTHING", (uuid.uuid4(),eid,TENANT,ctype,json.dumps(val),conf))

def add_rel(f, t, k, c=1.0):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM relationships WHERE from_entity_id=%s AND to_entity_id=%s AND kind=%s AND tenant_id=%s", (f,t,k,TENANT))
        if cur.fetchone(): return
        cur.execute("INSERT INTO relationships (id,tenant_id,from_entity_id,to_entity_id,kind,confidence) VALUES(%s,%s,%s,%s,%s,%s)", (uuid.uuid4(),TENANT,f,t,k,c))

# ── CQL Context Templates by Domain ─────────────────────────────
CQL_CONTEXTS = {
    "BYOVD": {
        "cql": [
            "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| CommandLine REGEX \"\\\\.sys\"\n| AND (ProcessName IN (\"rundll32.exe\", \"sc.exe\", \"pnputil.exe\") OR CommandLine REGEX \"CreateService|LoadDriver|NtLoadDriver|ZwLoadDriver\")\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine, ParentProcessName])",
            "#event.dataset = falcon.host\n| event.category = FileActivity\n| FileName REGEX \"\\\\.sys$\"\n| AND FilePath REGEX \"drivers|system32\"\n| table([timestamp, ComputerName, UserName, FileName, FilePath, ProcessName])",
        ],
        "process_tree": "rundll32.exe → loads .sys driver OR sc.exe create + start → loads .sys OR pnputil.exe /add-driver → loads .sys",
        "context": "Bring Your Own Vulnerable Driver (BYOBD/BYOVD) attacks load legitimate signed drivers with known vulnerabilities, then exploit them for kernel-level access. The driver is typically dropped to disk first (file write), then loaded via service creation (sc.exe), rundll32, or pnputil. Look for .sys file writes followed by driver load events from unusual parent processes.",
        "related_techniques": ["T1068", "T1543.003", "T1055.001"],
    },
    "lateral_movement": {
        "cql": [
            "#event.dataset = falcon.host\n| event.category = NetworkActivity\n| NetworkConnect_...Port IN (445, 135, 5985, 5986, 3389, 22)\n| AND (ProcessName IN (\"svchost.exe\", \"lsass.exe\", \"mmc.exe\", \"powershell.exe\", \"psexec64.exe\") OR ImageFileName REGEX \"PSEXESVC\")\n| groupby([ComputerName, NetworkConnect_...IP, NetworkConnect_...Port, ProcessName])\n| count > 5\n| table([ComputerName, NetworkConnect_...IP, NetworkConnect_...Port, ProcessName, count])",
            "#event.dataset = falcon.host\n| (ProcessName = \"cmd.exe\" AND ParentProcessName IN (\"mmc.exe\", \"wuauclt.exe\", \"svchost.exe\"))\n| OR CommandLine REGEX \"\\\\\\\\[A-Z0-9]\\\\.*-c|winrs|rundll32.*\\\\\\\\.*dll\",\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine, ParentProcessName])",
        ],
        "process_tree": "mmc.exe → cmd.exe (WMI lateral) OR svchost.exe → cmd.exe (service exec) OR psexec64.exe → PSEXESVC.exe → cmd.exe OR winrm/rs.exe → powershell.exe",
        "context": "Lateral movement via SMB (445), WMI (135), WinRM (5985), RDP (3389). Key parent-child patterns: mmc.exe spawning cmd.exe (WMI), PSEXESVC running commands, svc host with unusual network connections. Monitor for administrative tools run from unexpected sources.",
        "related_techniques": ["T1021.001", "T1021.002", "T1047", "T1021.006"],
    },
    "credential_access": {
        "cql": [
            "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| (ProcessName IN (\"lsass.exe\", \"mimikatz.exe\", \"procdump.exe\", \"rundll32.exe\", \"taskmgr.exe\") AND CommandLine REGEX \"lsass|sekurlsa|logonpasswords|lsadump|procdump.*lsass|comsvcs.*MiniDump.*lsass\")\n| OR (TargetProcessName = \"lsass.exe\" AND ProcessName NOT IN (\"svchost.exe\", \"csrss.exe\", \"smss.exe\", \"MsMpEng.exe\"))\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine, TargetProcessName])",
            "#event.dataset = falcon.host\n| CommandLine REGEX \"kerberos|as-rep|kerberoast|changepassword|setentpticket|sekurlsa|lsadump|dcsync\"\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine])",
        ],
        "process_tree": "mimikatz.exe → lsass.exe memory read OR procdump.exe -ma lsass → dump OR rundll32.exe comsvcs.dll MiniDump → lsass OR taskmgr.exe → lsass dump",
        "context": "Credential access via LSASS memory dumping, Kerberos attacks, and SAM database extraction. Key indicator: any process accessing lsass.exe other than legitimate system processes. Also watch for Kerberos tooling (Rubeus, Kekeo) via command-line patterns.",
        "related_techniques": ["T1003.001", "T1003.002", "T1558", "T1110.003"],
    },
    "persistence": {
        "cql": [
            "#event.dataset = falcon.host\n| event.category = RegistryActivity\n| RegistryKeyPath REGEX \"Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\(Run|RunOnce|RunServices|Explorer|Policies)\"\n| OR RegistryKeyPath REGEX \"System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\[^\\\\\\\\]+\\\\\\\\ImagePath\"\n| table([timestamp, ComputerName, UserName, RegistryKeyPath, RegistryValue, ProcessName])",
            "#event.dataset = falcon.host\n| (CommandLine REGEX \"schtasks.*/create\" OR CommandLine REGEX \"sc\\\\.exe.*create\")\n| AND UserName NOT REGEX \"NT AUTHORITY|SYSTEM$\"\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine])",
        ],
        "process_tree": "reg.exe add HKCU\\...\\Run → persistence OR schtasks.exe /create → scheduled task OR sc.exe create → service OR wmic.exe /namespace → WMI subscription",
        "context": "Common persistence mechanisms: Registry Run keys, scheduled tasks, service creation, WMI event subscriptions, Startup folder. Legitimate admins also use these — filter by user context and parent process. New Run key values from non-admin users are high-signal.",
        "related_techniques": ["T1547.001", "T1053.005", "T1543.003", "T1546.003"],
    },
    "defense_evasion": {
        "cql": [
            "#event.dataset = falcon.host\n| (CommandLine REGEX \"-bypass|-noprofile|-executionpolicy|hidden|\\\\-enc|\\\\-ec\" AND ProcessName = \"powershell.exe\")\n| OR (ProcessName IN (\"wmic.exe\", \"mshta.exe\", \"certutil.exe\", \"bitsadmin.exe\", \"mavinject.exe\") AND CommandLine NOT REGEX \"known_admin_script\")\n| OR CommandLine REGEX \"amsi\\\\.dll|etw|DisableRealtimeMonitoring|Set-MpPreference\"\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine])",
        ],
        "process_tree": "powershell.exe -enc → decoded payload OR mshta.exe → script execution OR certutil.exe -urlcache → download OR mavinject.exe → DLL injection",
        "context": "Defense evasion via AMSI bypass, ETW patching, LOLBin abuse, and AV disabling. PowerShell with -bypass/-enc flags is the most common. Watch for certutil/bitsadmin downloads, mshta executing scripts, and any attempt to disable Defender or patch AMSI/ETW.",
        "related_techniques": ["T1059.001", "T1218", "T1562.001", "T1055"],
    },
    "ransomware": {
        "cql": [
            "#event.dataset = falcon.host\n| (CommandLine REGEX \"vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|shadowcopy.*delete|fsutil.*usn\")\n| OR (FileName REGEX \"\\\\.(encrypted|locked|crypt|readme_instructions|HOW_TO_DECRYPT|DECRYPT)\")\n| OR (event.category = FileActivity AND count_by_process > 1000 AND FileName REGEX \"\\\\.(doc|xls|pdf|jpg|png|mdb|bak|zip)$\")\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine, FileName])",
        ],
        "process_tree": "vssadmin.exe delete shadows → wbadmin.exe delete catalog → bcdedit.exe /set recoveryenabled No → mass file encryption → ransom note drop",
        "context": "Ransomware kill chain: disable recovery (vssadmin/wbadmin/bcdedit) → encrypt files → drop ransom note. Key early indicator: volume shadow copy deletion commands. Mass file renames with sequential patterns. Also watch for ESXi targeting (via SSH).",
        "related_techniques": ["T1486", "T1490", "T1027", "T1070.004"],
    },
    "cloud": {
        "cql": [
            "#event.dataset = aws:cloudtrail\n| eventName IN (\"AssumeRole\", \"GetAuthorizationToken\", \"PutUserPolicy\", \"AttachUserPolicy\", \"CreateAccessKey\", \"ConsoleLogin\")\n| AND sourceIPAddress NOT IN (known_corporate_ranges)\n| table([eventTime, userIdentity.arn, eventName, sourceIPAddress, userAgent])",
            "#event.dataset = o365:management\n| Operation IN (\"UserLogin\", \"New-InboxRule\", \"Set-Mailbox\", \"Add-MailboxPermission\", \"Set-UserPassword\")\n| AND ClientIP NOT IN (known_corporate_ranges)\n| table([CreationTime, UserId, Operation, ClientIP, ClientAppUsed])",
        ],
        "process_tree": "Phishing → cloud console login → create inbox rule (hide forwarding) → add mailbox permissions → exfiltrate via email OR AssumeRole chain → access S3/EC2",
        "context": "Cloud attack patterns: BEC via inbox rule manipulation, credential stuffing, role assumption chains, key creation. Monitor for logins from unusual IPs, new inbox rules (especially forwarding), privilege escalation via policy attachment, and AssumeRole chains across accounts.",
        "related_techniques": ["T1078", "T1110.003", "T1530", "T1562.008"],
    },
    "supply_chain": {
        "cql": [
            "#event.dataset = falcon.host\n| event.category = ProcessActivity\n| (ImageFileName REGEX \"AppData|ProgramData|Temp\" AND (ProcessName IN (\"svchost.exe\", \"taskhostw.exe\", \"RuntimeBroker.exe\") OR FileName REGEX \"\\\\.dll$\"))\n| OR (ProcessName IN (\"msiexec.exe\", \"msedgewebview2.exe\") AND CommandLine REGEX \"http\")\n| table([timestamp, ComputerName, UserName, ProcessName, CommandLine, ImageFileName])",
        ],
        "process_tree": "msiexec.exe /i http://malicious.com/payload.msi → installs trojanized app OR software update service → downloads replaced DLL → dllsideload",
        "context": "Supply chain compromise: trojanized installers, DLL side-loading, poisoned updates, NPM/PyPI typosquatting. Key indicator: legitimate processes (svchost, taskhostw) running from AppData/Temp. MSI installs from HTTP. Software updaters fetching from unusual domains.",
        "related_techniques": ["T1195.002", "T1574.002", "T1195.001"],
    },
}

# ── Map entities to CQL context domains ─────────────────────────
KEYWORD_MAP = {
    "BYOVD": ["driver", "byovd", "byobd", "vulnerable driver", "loldriver", "kernel driver"],
    "lateral_movement": ["lateral", "smb", "psexec", "wmi", "winrm", "rdp", "ssh", "pass-the-hash", "pass-the-ticket"],
    "credential_access": ["credential", "lsass", "mimikatz", "dcsync", "kerberoast", "as-rep", "sam", "ntlm", "password"],
    "persistence": ["persistence", "run key", "scheduled task", "startup", "wmi subscription", "service creation", "autorun"],
    "defense_evasion": ["evasion", "amsi", "etw", "bypass", "lolbin", "lolbas", "certutil", "mshta", "hidden", "encoded"],
    "ransomware": ["ransomware", "encrypt", "vssadmin", "shadow copy", "wbadmin", "recovery", "crypt"],
    "cloud": ["cloud", "aws", "azure", "gcp", "o365", "office 365", "assume role", "inbox rule", "s3", "blob"],
    "supply_chain": ["supply chain", "typosquatting", "dll side", "trojanized", "poisoned", "dependency confusion"],
}

# ── Phase 1: Add CQL context claims to relevant entities ─────────
print("\n=== Phase 1: CQL Context Enrichment ===")

with conn.cursor() as cur:
    cur.execute("""
        SELECT e.id, e.kind, e.canonical_name, 
               COALESCE(string_agg(c.value::text, ' '), '') as claim_text
        FROM entities e
        LEFT JOIN claims c ON c.entity_id = e.id
        WHERE e.tenant_id = %s
        GROUP BY e.id, e.kind, e.canonical_name
    """, (TENANT,))
    entities = cur.fetchall()

enriched = 0
for eid, kind, name, claim_text in entities:
    combined = f"{name} {claim_text or ''}".lower()
    matched_domains = []

    for domain, keywords in KEYWORD_MAP.items():
        if any(kw in combined for kw in keywords):
            matched_domains.append(domain)

    # Also match by kind
    if kind == "driver" and "BYOVD" not in matched_domains:
        matched_domains.append("BYOVD")
    if kind == "attack_pattern" and not matched_domains:
        # Try to match by common technique names
        if any(w in combined for w in ["initial access", "execution", "privilege", "defense evasion"]):
            for domain, keywords in KEYWORD_MAP.items():
                if any(kw in combined for kw in keywords):
                    matched_domains.append(domain)

    if not matched_domains:
        continue

    # Build enrichment claim
    cql_queries = []
    process_trees = []
    contexts = []
    related_techs = set()

    for domain in matched_domains:
        ctx = CQL_CONTEXTS.get(domain)
        if not ctx: continue
        cql_queries.extend(ctx["cql"])
        process_trees.append(ctx["process_tree"])
        contexts.append(ctx["context"])
        related_techs.update(ctx.get("related_techniques", []))

    if cql_queries:
        add_claim(eid, "detection_detail", {
            "assertion": f"CQL investigation context for {name}: {len(matched_domains)} domain(s) — {', '.join(matched_domains)}. Process trees: {'; '.join(process_trees[:3])}",
            "cql_queries": cql_queries,
            "process_trees": process_trees,
            "investigation_context": " ".join(contexts),
            "related_techniques": list(related_techs),
            "detection_type": "cql_investigation_guide",
            "tags": ["cql", "investigation-guide", "crowdstrike"] + matched_domains,
        }, conf=0.8)
        enriched += 1

    # Link to related technique entities
    for tech_id in related_techs:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM entities WHERE mitre_attack_id=%s AND tenant_id=%s LIMIT 1", (tech_id, TENANT))
            r = cur.fetchone()
            if r and r[0] != eid:
                add_rel(eid, r[0], "investigation_context_for", 0.8)

    if enriched % 200 == 0:
        print(f"  ... {enriched} enriched")

print(f"  CQL context enriched: {enriched} entities")

# ── Phase 2: Build investigation guide relationships ────────────
print("\n=== Phase 2: Investigation Guide Relationships ===")

# Link detection rules to the techniques they detect (via MITRE IDs in refs)
with conn.cursor() as cur:
    cur.execute("SELECT id, canonical_name, external_refs FROM entities WHERE kind='detection' AND tenant_id=%s", (TENANT,))
    detections = cur.fetchall()

rc = 0
for det_id, det_name, det_refs in detections:
    if not det_refs or isinstance(det_refs, str): det_refs = {}
    attack_ids = det_refs.get("attack_ids", det_refs.get("mitre_ids", []))
    if not attack_ids: continue
    for aid in attack_ids:
        with conn.cursor() as cur2:
            cur2.execute("SELECT id FROM entities WHERE mitre_attack_id=%s AND tenant_id=%s LIMIT 1", (aid, TENANT))
            r = cur2.fetchone()
            if r:
                add_rel(det_id, r[0], "detects", 0.9)
                rc += 1

print(f"  Detection→Technique links: {rc}")

# ── Phase 3: Actor→Technique deep links ─────────────────────────
print("\n=== Phase 3: Actor→Technique Deep Links ===")

# From threat actor claims, extract technique IDs and link
with conn.cursor() as cur:
    cur.execute("""
        SELECT e.id, e.canonical_name, c.value::text
        FROM entities e
        JOIN claims c ON c.entity_id = e.id
        WHERE e.kind='threat_actor' AND e.tenant_id=%s AND c.claim_type='technique'
    """, (TENANT,))
    actor_techs = cur.fetchall()

arc = 0
for actor_id, actor_name, claim_text in actor_techs:
    # Extract T-prefixed IDs from claim text
    tech_ids = re.findall(r'(T\d{4}(?:\.\d{3})?)', claim_text)
    for tid in tech_ids:
        with conn.cursor() as cur2:
            cur2.execute("SELECT id FROM entities WHERE mitre_attack_id=%s AND tenant_id=%s LIMIT 1", (tid, TENANT))
            r = cur2.fetchone()
            if r:
                add_rel(actor_id, r[0], "uses_technique", 0.85)
                arc += 1

print(f"  Actor→Technique links: {arc}")

# ── Phase 4: CVE→Detection cross-pollination ────────────────────
print("\n=== Phase 4: CVE→Detection Cross-Pollination ===")

# For CVEs with exploit/KEV status, link to relevant detection rules
with conn.cursor() as cur:
    cur.execute("""
        SELECT e.id, e.canonical_name
        FROM entities e
        JOIN claims c ON c.entity_id = e.id
        WHERE e.kind='cve' AND e.tenant_id=%s 
        AND (c.value::text LIKE '%%kev%%' OR c.value::text LIKE '%%exploit%%')
    """, (TENANT,))
    exploited_cves = cur.fetchall()

cve_det = 0
for cve_id, cve_name in exploited_cves[:500]:
    # Find detection rules that might apply (broad match on CVE keywords)
    cve_num = cve_name.replace("CVE-", "").replace("-", "")
    with conn.cursor() as cur2:
        cur2.execute("SELECT id FROM entities WHERE kind='detection' AND canonical_name ILIKE '%%exploit%%' AND tenant_id=%s LIMIT 3", (TENANT,))
        for r in cur2.fetchall():
            add_rel(cve_id, r[0], "detectable_by", 0.7)
            cve_det += 1

print(f"  CVE→Detection links: {cve_det}")

conn.close()
print(f"\n✅ Inter-knowledge enrichment complete")
