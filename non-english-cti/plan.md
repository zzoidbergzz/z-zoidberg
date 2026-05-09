# Non-English CTI Collection & Ingestion Pipeline — Plan

> **Framing**: Non-English CTI is a collection-engineering problem, not just translation. Value = earlier local reporting, regional victimology, local software vulns, adversary-language chatter, sector-specific advisories, and context lost in English summaries.

## Research Phase

### Step 1: Source Discovery — National CERTs/CSIRTs
- [ ] Scrape FIRST member directory for all non-English teams
- [ ] Scrape Trusted Introducer for EU/EEA CSIRTs
- [ ] Scrape EU CSIRTs Network list
- [ ] Research APNIC/LACNIC/RIPE regional references
- [ ] For each: identify RSS, Atom, API, sitemap, email bulletin, PDF, HTML, JSON endpoints
- [ ] Languages: FR, DE, ES, PT, PL, UK, JA, KO, ZH, RU, AR, FA, TR, HE, ID, VI, TH, HI, UR
- [ ] Store in source catalogue (see data model below)

### Step 2: Source Discovery — National Vulnerability Databases
- [ ] Japan: JVN / JVN iPedia (jvndb.jvn.jp)
- [ ] China: CNVD (cnvd.org.cn) / CNNVD (cnnvd.org.cn)
- [ ] Russia: BDU / FSTEC (bdu.fstec.ru)
- [ ] Korea: KISA/KrCERT advisories
- [ ] Spain: INCIBE vulnerability database
- [ ] Brazil: CERT.br advisories
- [ ] Poland: CERT Polska
- [ ] For each: map fields to CVE, CWE, CVSS, CPE, affected product, vendor, exploit status, patch status, local ID
- [ ] Compare disclosure timing, CVE coverage, local product coverage, machine-readability

### Step 3: Source Discovery — Regional Security Vendors & Research
- [ ] China: 360 Netlab, QiAnXin TI Center, NSFOCUS, VenusTech, ThreatBook
- [ ] Korea: AhnLab ASEC, Kaspersky Korea, ESTsecurity
- [ ] Japan: JPCERT, LAC Co, FFRI, SiteLock
- [ ] Russia: Kaspersky RU, Group-IB (F.A.C.C.T.), Positive Technologies
- [ ] Eastern Europe: ESET, VirusTotal (multi-lang), CERTs
- [ ] Latin America: INCIBE, CSIRT AM, local vendors
- [ ] Middle East: regional security firms
- [ ] South/Southeast Asia: local vendors
- [ ] Prioritise: IOCs, malware analysis, YARA/Sigma/Snort, C2, actor names, malware names, lure docs, sectors, TTPs

### Step 4: Source Discovery — Public Social/Forum/News
- [ ] Identify lawful public-only sources for incident reports, hacktivist claims, ransomware victims
- [ ] Exclude: credentialed access, bypasses, stolen data, malware samples, deception
- [ ] Focus: public metadata, URLs, timestamps, claim text, actor aliases, victims, sectors

### Step 5: Source Discovery — Local Tech/Security News
- [ ] Identify local-language news sites reporting breaches, ransomware, government cyber incidents
- [ ] Before English outlets
- [ ] Entity extraction targets: victims, sectors, countries, dates, ransomware groups, regulators

### Step 6: Build Source Catalogue
- [ ] 150+ sources with full metadata (see data model)
- [ ] Score: intelligence value (1-5), reliability (1-5), legal/ethical risk (1-5)
- [ ] Collection priority ranking
- [ ] Top 30 for immediate ingestion

### Step 7: Language/Region Priority Matrix
- [ ] Map languages to strategic value, source types, translation difficulty, validation needs

## Architecture Phase

### Step 8: Python Ingestion Architecture Design
```
Source registry (YAML/DB)
  ↓
Scheduler (APScheduler / cron)
  ↓
Fetcher: RSS / API / HTML / PDF / social-public
  ↓
Raw evidence store (S3/FS + metadata in PostgreSQL)
  ↓
Parser/extractor (trafilatura / feedparser / pypdf)
  ↓
Language detection (lingua-language-detector)
  ↓
Translation to English (LibreTranslate self-hosted → optional DeepL)
  ↓
IOC/CVE/entity/TTP extraction (iocextract, spaCy, Stanza, regex)
  ↓
Deduplication and clustering (content hash, fuzzy title, IOC overlap)
  ↓
Scoring and analyst review queue
  ↓
Export: MISP / OpenCTI / STIX 2.1 / TAXII 2.1 / SIEM
```

### Step 9: Data Model — Normalised Record Schema
| Field | Type | Description |
|-------|------|-------------|
| source_id | UUID | Unique source identifier |
| source_url | URL | Original URL |
| canonical_url | URL | Deduplicated canonical |
| title_original | text | Original-language title |
| title_en | text | English translation |
| body_original | text | Original full text |
| body_en | text | English translation |
| language_detected | ISO 639-1 | Detected language |
| country | ISO 3166-1 alpha-2 | Source country |
| region | text | Geographic region |
| source_type | enum | cert/vulndb/vendor/social/news |
| published_at | timestamp | Original publication |
| collected_at | timestamp | Collection timestamp |
| hash_content | sha256 | Content hash |
| extracted_iocs | jsonb | IPs, domains, hashes, URLs, emails |
| extracted_cves | jsonb | CVE identifiers |
| extracted_ttps | jsonb | MITRE ATT&CK refs |
| extracted_actors | jsonb | Threat actor names/aliases |
| extracted_malware | jsonb | Malware family names |
| extracted_tools | jsonb | Tools referenced |
| extracted_victims | jsonb | Victim orgs/sectors |
| sectors | jsonb | Industry sectors |
| confidence_score | float 0-1 | Item confidence |
| reliability_score | float 0-1 | Source reliability |
| analyst_status | enum | new/reviewed/approved/rejected |
| export_status | jsonb | MISP/OpenCTI/STIX export status |
| citations | jsonb | References and source links |
| translation_method | text | libretranslate/deepl/manual |
| translation_confidence | float 0-1 | Translation quality estimate |
| raw_html_path | text | Path to stored raw HTML/PDF |

### Step 10: Python Library Stack
- **HTTP**: httpx (async), aiohttp
- **Feed parsing**: feedparser
- **HTML extraction**: trafilatura, readability-lxml, BeautifulSoup
- **Browser** (rare): Playwright
- **PDF**: pypdf, pymupdf
- **Language detection**: lingua-language-detector
- **Translation**: LibreTranslate/Argos (self-hosted), deep-translator (multi-engine wrapper)
- **NLP**: spaCy, Stanza, multilingual transformers
- **IOC extraction**: iocextract, custom regex
- **CTI modelling**: stix2, pymisp, pycti
- **Storage**: PostgreSQL, SQLite (prototype), OpenSearch (FTS)
- **Queues**: Redis Queue, Celery, or Kafka
- **Scheduling**: APScheduler, cron, Prefect

### Step 11: Quality Controls
- [ ] Preserve original + translated side-by-side
- [ ] Never overwrite source with machine translation
- [ ] Translation confidence + back-translation sampling for high-priority
- [ ] Dedup: canonical URL, content hash, fuzzy title, CVE/IOC overlap, pub date
- [ ] Source reliability ≠ item confidence (track separately)
- [ ] Flag: uncertain translations, slang, actor aliases, homographs, machine-translated proper nouns
- [ ] Analyst review gate for: high-impact attribution, victim claims, exploit-in-the-wild

### Step 12: Security & Compliance
- [ ] Respect robots.txt and source ToS
- [ ] Rate limits + caching
- [ ] No paywall bypass, auth bypass, CAPTCHA bypass
- [ ] No malware samples or stolen data
- [ ] Treat URLs/docs/IOCs as potentially malicious
- [ ] Controlled egress environment
- [ ] Safe raw HTML/PDF storage
- [ ] No untrusted content in analyst browsers
- [ ] Audit logs for every collected item
- [ ] Source attribution + collection timestamps

## Implementation Phase

### Step 13: Prototype — Phase 1: RSS/API Collectors
- [ ] Source registry (YAML config)
- [ ] RSS fetcher using feedparser
- [ ] API fetcher for JSON endpoints
- [ ] Raw evidence storage
- [ ] Feed status monitoring

### Step 14: Prototype — Phase 2: HTML/Sitemap Crawlers
- [ ] Static HTML advisory parser (trafilatura)
- [ ] Sitemap discovery + crawl
- [ ] robots.txt compliance checker

### Step 15: Prototype — Phase 3: PDF Report Ingestion
- [ ] PDF download + text extraction
- [ ] Structured metadata extraction from PDFs

### Step 16: Prototype — Phase 4: Translation Pipeline
- [ ] Language detection
- [ ] LibreTranslate self-hosted instance (Docker)
- [ ] Two-track: routine (LibreTranslate) + high-value (optional DeepL)
- [ ] Translation confidence scoring
- [ ] Back-translation quality sampling

### Step 17: Prototype — Phase 5: Enrichment
- [ ] IOC extraction pipeline
- [ ] CVE extraction + enrichment
- [ ] Entity extraction (spaCy multilingual)
- [ ] TTP mapping to MITRE ATT&CK

### Step 18: Prototype — Phase 6: CTI Platform Integration
- [ ] STIX 2.1 bundle export
- [ ] MISP event creation workflow
- [ ] OpenCTI ingestion workflow
- [ ] TAXII 2.1 server/client

### Step 19: Analyst Interface
- [ ] Review queue UI
- [ ] Side-by-side original + translation view
- [ ] Expand original article in UI
- [ ] Confidence/reliability scores visible
- [ ] Analyst feedback loop → quality scoring

### Step 20: Operational Runbook & Maintenance
- [ ] Source health check automation
- [ ] Translation QA procedures
- [ ] Rate limit monitoring
- [ ] Analyst onboarding guide
- [ ] Incident response for source changes

## Repository Layout
```
non-english-cti/
├── plan.md                    # This file
├── catalogue/
│   ├── sources.yaml           # Full source catalogue (150+)
│   ├── top30.yaml             # Top 30 immediate ingestion
│   └── priority_matrix.yaml   # Language/region priority matrix
├── src/
│   ├── __init__.py
│   ├── registry.py            # Source registry loader
│   ├── fetchers/
│   │   ├── rss.py             # RSS/Atom fetcher
│   │   ├── api.py             # JSON API fetcher
│   │   ├── html.py            # HTML advisory fetcher
│   │   ├── pdf.py             # PDF report fetcher
│   │   └── social.py          # Public social monitoring
│   ├── parsers/
│   │   ├── feed_parser.py     # Feed content parser
│   │   ├── html_parser.py     # HTML content extraction
│   │   └── pdf_parser.py      # PDF text extraction
│   ├── translation/
│   │   ├── detector.py        # Language detection
│   │   ├── translator.py      # Translation pipeline
│   │   └── confidence.py      # Translation QA
│   ├── extraction/
│   │   ├── ioc.py             # IOC extraction
│   │   ├── cve.py             # CVE extraction
│   │   ├── entity.py          # Named entity extraction
│   │   ├── ttp.py             # TTP mapping
│   │   └── dedup.py           # Deduplication
│   ├── models/
│   │   ├── record.py          # Normalised record schema
│   │   └── source.py          # Source metadata model
│   ├── export/
│   │   ├── stix.py            # STIX 2.1 export
│   │   ├── misp.py            # MISP event creation
│   │   ├── opencti.py         # OpenCTI ingestion
│   │   └── taxii.py           # TAXII 2.1 client
│   ├── storage/
│   │   ├── db.py              # PostgreSQL storage
│   │   └── raw_store.py       # Raw evidence store
│   └── scheduler.py           # Collection scheduling
├── docker/
│   ├── docker-compose.yml     # LibreTranslate, PostgreSQL, Redis
│   └── Dockerfile
├── config/
│   ├── sources/               # Per-source YAML configs
│   └── pipeline.yaml          # Pipeline configuration
├── tests/
│   └── ...
├── docs/
│   ├── runbook.md             # Operational runbook
│   └── analyst_guide.md       # Analyst onboarding guide
└── scripts/
    ├── seed_sources.py        # Load source catalogue to DB
    └── health_check.py        # Source health verification
```

## Language Priority Order
| Priority | Language | Region | Why |
|----------|----------|--------|-----|
| 1 | Chinese (ZH) | CN, TW | Local vuln ecosystems, vendor research, botnet/IoT, APT |
| 2 | Russian/Ukrainian (RU/UK) | RU, UA | Vuln DBs, cybercrime, wartime cyber, hacktivism |
| 3 | Korean (KO) | KR | DPRK reporting, financial malware, AhnLab/KISA |
| 4 | Japanese (JA) | JP | JVN/JPCERT, local vendor/product vulns |
| 5 | Spanish/Portuguese (ES/PT) | LATAM, ES, PT, BR | CERTs, ransomware victimology, telecom/govt |
| 6 | French/German/Polish (FR/DE/PL) | EU | CERT ecosystems, EU advisories, regional malware |
| 7 | Arabic/Persian/Turkish/Hebrew (AR/FA/TR/HE) | MENA | Conflict, hacktivism, govt/telecom/energy |
| 8 | Vietnamese/Thai/Indonesian (VI/TH/ID) | SE Asia | Banking malware, fraud, regional CERTs |
