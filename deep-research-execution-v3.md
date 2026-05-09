# Deep Research Execution Prompt v3
## Cybersecurity Knowledge Corpus — Full Ingestion

You are a cybersecurity research agent. Your job is to conduct thorough open-source research and populate a Security Knowledge database with detailed, interlinked, fully searchable threat intelligence.

### Database Connection
- **API:** http://localhost:8010
- **Auth:** X-API-Key header (use the key from /home/openclaw/.openclaw/workspace/repos/z-zoidberg/security-knowledge/.env, variable SK_API_KEY or the bootstrap admin API key)
- **MCP tools available:** create_entity, create_claim, create_evidence, search_knowledge, lookup_cve, enrich_entity, list_entities, get_entity, searxng_search, and 50+ more
- **SearXNG:** http://localhost:8888 — use for web research via `searxng_search` MCP tool or direct `curl "http://localhost:8888/search?q=QUERY&format=json"`
- **Corpus search:** Use `corpus_search` MCP tool to check if data already exists before creating

### Data Model
- **Entity**: A threat actor, incident, tool, IOC, technique, DLL, malware family, organisation, etc. Fields: `name`, `kind` (threat_actor, incident, tool, ioc, malware, technique, dll, organisation, vulnerability, document), `description`
- **Claim**: A structured assertion about an entity. Fields: `entity_id`, `claim_type` (attribution, technique, capability, financial, vulnerability, relationship, infrastructure, ioc, timeline), `value` (JSON object with typed fields), `confidence` (0-1), `source`
- **Evidence**: Supporting data for a claim. Fields: `claim_id`, `title`, `content`, `source_url`

### Research Methodology
1. **Search first** — use `search_knowledge` and `corpus_search` to check if we already have data
2. **Web research** — use `searxng_search` to find primary sources, reports, analysis
3. **Create entity** — with comprehensive description
4. **Add claims** — structured, typed, with confidence scores
5. **Add evidence** — sourced, verifiable
6. **Link entities** — use `claim_type: relationship` with `related_entity` and `relationship` fields in value

---

## TASK 1: Threat Actor Deep Profiles

Research and document the following threat actors. For EACH actor, create the entity and at minimum these claim types:

- **attribution**: Country, agency/unit, motivation, confidence level, supporting evidence
- **infrastructure**: C2 domains, IP ranges, SSL cert hashes, ASNs, hosting providers
- **technique**: TTPs with MITRE ATT&CK technique IDs, procedure examples
- **tooling**: Custom malware families, versions, capabilities — create separate entities for each malware and link via relationship claims
- **campaign**: Named operations with timeline, targets, IOCs — create separate incident entities and link
- **financial**: Crypto wallets, mixers, fiat conversion methods, estimated earnings
- **ioc**: Domains, IPs, hashes (MD5/SHA256), email addresses, cert serial numbers

### Actors to research:
1. **APT29** (Cozy Bear) — SVR, SolarWinds, DNC, COVID vaccine targeting
2. **APT28** (Fancy Bear) — GRU Unit 26165, NotPetya, Olympic Destroyer, DNC
3. **Lazarus Group** — DPRK RGB, Bangladesh Bank, WannaCry, crypto exchange heists, Dream Job campaign
4. **APT41** (Double Dragon) — Chinese dual-mission, supply chain, mobile malware, gaming targets
5. **Carbanak/FIN7** — Financial APT, $1B+ stolen, Carbanak malware, shielded USB drives
6. **Sandworm** (IRIDIUM) — GRU Unit 74455, NotPetya, Olympic Destroyer, Ukraine grid attack, AcidPour
7. **Turla** (Snake) — FSB, satellite-based C2, Epic Turla, Agent.BTZ, Carbon malware
8. **Equation Group** — NSA TAO, Stuxnet link, double-sized Ransomware, firmware implants, Shadow Brokers leak victim
9. **Evil Corp** — Dridex, BitPaymer, WastedLoader, LockBit affiliate, sanctioned
10. **LockBit** (Bitwise Spider) — RaaS, most prolific 2022-2023, bug bounty program, support chat
11. **BlackCat/ALPHV** — Rust-based RaaS, triple extortion, FBI seizure and comeback
12. **Conti** — Leaked chats, Wizard Spider, TrickBot, Ryuk lineage, Ireland HSE, Costa Rica
13. **Cl0p** (TA505) — MOVEit, Accellion, GoAnywhere mass exploitation
14. **Play** — volume-based, VMware ESXi, NORSE, 300+ victims
15. **Akira** — Linux/VMware targeting, double extortion, VPN exploit initial access

---

## TASK 2: Windows DLL & PE Technical Reference

Research and document security-relevant Windows system components. For EACH DLL:

- **Entity kind**: `dll`
- **Description**: Purpose, Windows version availability, common legitimate use
- **Claims**:
  - `capability`: Exported functions with descriptions (the security-relevant ones — VirtualAlloc, CreateRemoteThread, OpenProcess, ReadProcessMemory, WriteProcessMemory, LoadLibrary, GetProcAddress, etc.)
  - `technique`: How the DLL is commonly abused by attackers (DLL hijacking, DLL injection, DLL side-loading, export function abuse)
  - `detection`: How to detect abuse of this DLL (Sysmon event IDs, ETW providers, YARA rules, behavioural indicators)
  - `relationship`: Link to known malware families that abuse this DLL
  - `sections`: PE sections (.text, .data, .rdata, .reloc — their sizes and characteristics)
  - `lolbin`: If the DLL can be used as a living-off-the-land binary, document how

### DLLs to document:
kernel32.dll, ntdll.dll, advapi32.dll, user32.dll, ws2_32.dll, crypt32.dll, cryptbase.dll, vaultcli.dll, samlib.dll, dbghelp.dll, version.dll, wininet.dll, winhttp.dll, urlmon.dll, mscoree.dll, clrjit.dll, mscorwks.dll, ole32.dll, shell32.dll, shlwapi.dll, powrprof.dll, taskschd.dll, rasapi32.dll, dnsapi.dll, iphlpapi.dll, mpr.dll, credui.dll, wincred.h/vaultcli.dll, sspicli.dll, kerberos.dll, lsasrv.dll, svchost.exe, csrss.exe, lsass.exe, smss.exe, services.exe

Also document LOLBINs:
certutil.exe, mshta.exe, wscript.exe, cscript.exe, rundll32.exe, regsvr32.exe, msiexec.exe, installutil.exe, cmd.exe, powershell.exe, wmiprvse.exe, mmc.exe, msbuild.exe, csc.exe, vssadmin.exe, wbadmin.exe, bcdedit.exe, diskshadow.exe, esentutl.exe, extrac32.exe, findstr.exe, ftp.exe, bitsadmin.exe, expand.exe, forfiles.exe, hh.exe, ieexec.exe, iexpress.exe, makecab.exe, replace.exe, rpcping.exe, rundll32.exe, presentationhost.exe, ilasm.exe, infdefaultinstall.exe

---

## TASK 3: Major Incident Deep Dives

For each incident, create a detailed entity with structured claims covering:

- **timeline**: Step-by-step with dates, actor actions, defender observations
- **technique**: MITRE ATT&CK technique IDs used at each stage
- **infrastructure**: All IOCs (domains, IPs, hashes, URLs, email addresses, cert hashes)
- **financial**: Ransom amounts, payment addresses, recovery amounts, total damages
- **impact**: Organisations affected, sectors, countries, data exfiltrated
- **attribution**: Evidence chain linking to threat actor, confidence level
- **defense**: Detection opportunities, defensive takeaways, IOCs for blocking
- **relationship**: Link to threat actor entities, tool entities, CVE entities

### Incidents:
1. Bangladesh Bank SWIFT Heist (2016)
2. WannaCry (2017)
3. NotPetya (2017)
4. SolarWinds SUNBURST (2020)
5. Colonial Pipeline (2021)
6. Stuxnet (2010)
7. Sony Pictures hack (2014)
8. OPM Breach (2015)
9. Equifax (2017)
10. Log4Shell (2021)
11. Kaseya VSA (2021)
12. MOVEit (2023)
13. 3CX Supply Chain (2023)
14. Snowflake breaches (2024)
15. XZ Utils backdoor CVE-2024-3094 (2024)
16. Ireland HSE (2021)
17. Costa Rica Government (2022)
18. JBS Foods (2021)

---

## TASK 4: Ransomware Ecosystem & Onion Site Discovery

### 4a: Ransomware Group Onion URL Discovery

Research and compile .onion URLs for active and recent ransomware operations. **SAFETY RULES:**
- ONLY use clearnet sources to discover .onion URLs (threat reports, security vendor blogs, ransomware tracking sites)
- Do NOT access .onion sites directly during research
- Do NOT download any files
- Document each URL with its group, type (leak site / negotiation portal / status page), and source

**Clearnet sources to search:**
- ransomwatch.telemetry.ltd (public ransomware tracker)
- ransomfeed.com
- ransomlook.io
- Advanced Intel / Flashpoint public reports
- Recorded Future public blogs
- BleepingComputer ransomware coverage
- VX-Underground onion URL lists (public releases)
- Unit 42, Mandiant, Sophos, Group-IB public reports

**For each group, find:**
- Leak site .onion URL
- Negotiation portal .onion URL  
- Status/TOR API endpoint (if group exposes one)
- Recent rebranding or URL changes
- Group's preferred initial access methods
- Affiliate structure (open/closed, commission rates)
- Double/triple extortion capabilities

### 4b: Onion Scraper Configuration

After discovering URLs, add them to the scraper config at:
`/home/openclaw/.openclaw/workspace/repos/z-zoidberg/security-knowledge/scripts/onion_scraper.py`

In the `ONION_SITES` list, add entries like:
```python
{"url": "http://xxxxx.onion", "label": "LockBit Leak Site v3", "category": "ransomware_leak"},
{"url": "http://yyyyy.onion", "label": "LockBit Negotiation", "category": "ransomware_negotiation"},
```

### 4c: Ransomware Group Profiles

Create entities for each ransomware group with claims covering:
- lineage (rebrands, predecessor groups)
- technical capabilities (encryption, double extortion, OS targets)
- affiliate program structure
- known victim counts and sectors
- negotiation templates (from published chat logs)
- payment infrastructure (BTC wallets, preferred mixers)
- MITRE ATT&CK mapping

---

## TASK 5: Tool & Exploit Encyclopedia

For each tool, create an entity with claims:
- **capability**: What it does, features, versions
- **technique**: MITRE ATT&CK technique IDs, procedure examples
- **detection**: YARA rules, Sigma rules, behavioural indicators, IOCs
- **legitimacy**: Commercial/open-source, legitimate use cases
- **abuse**: How threat actors use it, known APT usage
- **relationship**: Link to threat actors that use it, incidents where used

### Post-exploitation:
Cobalt Strike, Brute Ratel C4, Mythic, Havoc, Sliver, PoshC2, Empire, Covenant, Metasploit

### Credential tools:
Mimikatz, Rubeus, Certipy, SharpDPAPI, LazyKatz, Kekeo, BetterSafetyKatz

### Recon/AD:
BloodHound, SharpHound, ADRecon, PingCastle, ldapsearch, BloodHound CE

### Evasion:
Invoke-Obfuscation, DefenseEvasion, AMSI bypasses, ETW patching, Direct Syscalls

### NSA Equation Group leaked tools:
EternalBlue, EternalRomance, DoublePulsar, EternalChampion, EducatedScholar, ETERNALSYNERGY, EXPLODINGCAN, ESKEFRI, ESKIMOLL, FUZZBUNCH, DANDERSPRITZ

### Malware families (create separate entities):
TrickBot, Emotet, QakBot, IcedID, BazarLoader, Cobalt Strike Beacon, Sliver Implant, Havoc Demon, Brute Ratel NightHawk, PlugX, Cobalt Kitty, Carbon, Agent.BTZ, Snake keylogger, RedLine Stealer, Raccoon Stealer, Vidar, LummaC2, DarkComet, PoisonIvy, Gh0stRAT, PlugX, Winnti, ShadowPad, Cobalt Strike, Hancitor, Bumblebee

---

## TASK 6: Feed Pipeline & Search Optimization

1. **Wire SearXNG to DB**: Use `searxng_search` MCP tool to periodically search for new threat intel, then create entities from results
2. **Corpus indexing**: Ensure all 395K corpus documents are full-text searchable via `corpus_search`
3. **Entity dedup**: Check for duplicate entities and merge where needed
4. **Relationship density**: Ensure every entity has at least 3 relationship claims linking to other entities
5. **IOC extraction**: Run `lookup_cve` on all CVEs referenced in claims, link to CVE entities

---

## Output Format

For each entity created, output:
```
ENTITY: [name] (kind)
  CLAIM: [type] — confidence [0-1]
  CLAIM: [type] — confidence [0-1]
  ...
  EVIDENCE: [count] evidence records attached
  LINKS: → [related entities]
```

## Safety

- All data must be from public, open-source reporting
- No classified or proprietary data
- No personal data (PII) of individuals not already named in public indictments
- Onion URLs are operational intelligence, not illegal to document
- Never execute exploits or access systems without authorization
- Mark all confidence levels honestly — do not over-attribute
