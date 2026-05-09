# Offensive Security Repo Search Methodology

## Search Methods

### 1. GitHub Topics (curated, highest signal)
```
topic:c2-framework stars:>200
topic:ransomware stars:>50
topic:malware-samples stars:>100
topic:rootkit stars:>200
topic:privilege-escalation stars:>100
```

### 2. CVE-Driven Search
- Extract CVE IDs from Sigma rules, NVD, z.je SK platform
- Search: `{CVE-ID} exploit poc` on GitHub
- Focus on CVEs from last 2 years with CVSS > 7.0

### 3. MITRE ATT&CK Technique Search
- Map ATT&CK techniques from Sigma rules → GitHub search terms
- Priority techniques: T1059 (Command Scripting), T1548 (Abuse Elevation), T1055 (Process Injection), T1569 (System Services), T1078 (Valid Accounts)

### 4. Sigma Rule Keyword Extraction
- Parse Sigma rules for detection keywords (service names, process names, registry keys)
- Search GitHub for repos containing those exact strings
- Bridge script: `repo-scanner/sigma_github_bridge.py`

### 5. Ransomware Family Search
- Use the 35 malware families identified in our scan
- Search: `{family_name} ransomware analysis source`
- Cross-reference with Ransomware-Tool-Matrix for TTP mapping

### 6. Hash-Verified Samples
- 3,444 SHA256 hashes computed from repo files
- Cross-reference against VirusTotal, MalwareBazaar, InQuest
- Use as YARA rule testing corpus

## Current Corpus Stats

| Metric | Count |
|--------|-------|
| Repos scanned | 42 |
| Files analyzed | 37,444 |
| SHA256 hashes | 3,444 |
| Unique CVEs | 655 |
| ATT&CK techniques | 716 |
| Malware families | 35 |

## Repos on z.je

### ~/z-zoidberg/repos/ (cloned, 31 repos, 1.5GB)
- C2: Empire, Mythic, Havoc, merlin
- Kernel: CVE-2024-1086, linux-kernel-exploits, linux-kernel-defence-map, linux-exploit-suggester-2
- Malware: The-MALWARE-Repo, malware-samples
- Ransomware: Ransomware-Samples, Ransomware-Tool-Matrix, conti-pentester-guide-leak, ransomware
- Rootkit: TitanHide, Nidhogg, Diamorphine, hidden, Singularity, Chaos-Rootkit, ebpfkit, TripleCross, spectre
- Analysis: Qu1cksc0pe, PersistenceSniper, PrivEsc, awesome-malware-analysis
- Windows: CVE-2020-0796, awesome-windows-kernel-security-development

### ~/repo/ (pre-existing, 11 repos, 17GB)
- WindowsElevation (347MB, 1045 files, 137 CVEs)
- windows-kernel-exploits (426MB, 433 files, 108 CVEs)
- source-code-of-a-famous-OS (11GB)
- some-many-books (5.5GB)
- DeepZero, DrvEye, HackSys_HEVD_Exploits, ReactExploitGUI, UnknownKiller, winpwn, CVE-2020-12446

## Analysis Pipeline
1. `scan_repos.py` — extract hashes, CVEs, ATT&CK, families, IOCs
2. `github_search.py` — discover repos by category/CVE/technique
3. `sigma_github_bridge.py` — map Sigma rules → GitHub repos
4. Output: JSON per repo in ~/necti-data/repo-analysis/
