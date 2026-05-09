# Gap Analysis: Current State vs. Frontier CTI Corpus Specification

## What We Have

### Data
- 7,641 entities (34 kinds)
- 14,208 claims (attributions, TTPs, infrastructure, IOCs)
- 9,057 evidence records
- 395,860 corpus documents (349K CVEs, 47K exploits, GCVE)
- 622 LOLDrivers (malicious + vulnerable driver hashes + metadata)
- 686 threat actors (MITRE encyclopedia + vendor profiles)
- 19 DLL entities with exported functions
- 8 LOLBIN entities with detection guidance
- 12 NSA Equation Group tools
- 21 malware families
- 18 major incidents
- 20 onion URLs (12 ransomware groups)

### Infrastructure
- SK API: 124 endpoints, 59 MCP tools
- PostgreSQL + pgvector on 5433
- SearXNG on 8888 (JSON API)
- Tor on 9050
- DarkMoon Docker (pentest tools)
- Feed poller cron (4h NVD/KEV)
- IOC extractor cron (daily)
- STIX 2.1 export endpoint
- GraphQL endpoint
- Full-text search
- Enrichment API (11 providers)
- MITRE ATT&CK API (30+ query endpoints)

---

## GAPS vs. Frontier CTI Spec

### GAP 1: No YARA Rule Corpus
**Spec requires:** Parsed YARA rules with canonical hashes, namespaces, tags, modules
**Current:** Zero YARA rules in the database
**Action:** Import YARA rules from public repositories
- malware-ioc (strontic)
- YARA rules bundled with MalwareBazaar
- Elastic security YARA rules
- Neo23x0/signature-base

### GAP 2: No MISP Feed Integration
**Spec requires:** MISP events, objects, taxonomies, galaxies
**Current:** MISP listed as enrichment provider but no feed ingestion
**Action:** Configure MISP feed sync (public feeds: CIRCL, Botvrij.eu, MISP galaxies)

### GAP 3: No MalwareBazaar/Malpedia Samples
**Spec requires:** Malware samples with hashes, family naming, YARA, sandbox outputs
**Current:** Malware family names only (no sample hashes, no behaviour data)
**Action:** Import MalwareBazaar API data + Malpedia family metadata

### GAP 4: No Sysmon Config Analysis
**Spec requires:** Sysmon configs parsed as executable policies with semantic diffing
**Current:** Nothing
**Action:** Import and parse SwiftOnSecurity, Olaf Hartong, ion-storm configs; create Sysmon rule entities

### GAP 5: No C++/Code Analysis
**Spec requires:** AST parsing, function-level extraction, memory-safety signals, CWE mapping
**Current:** Nothing
**Action:** Not directly implementable without code analysis tooling — add as future capability. Document gap.

### GAP 6: No Binary Analysis Corpus
**Spec requires:** Function maps, CFG hashes, decompiler summaries, API call clusters
**Current:** PyGhidra MCP available but not used for corpus building
**Action:** Sample analysis pipeline for notable malware families

### GAP 7: Weak Provenance & Confidence Scoring
**Spec requires:** Per-record provenance, fetch hashes, extractor versions, component confidence scores
**Current:** Claims have source strings but no structured provenance; confidence is a float without breakdown
**Action:** Add provenance metadata to new records going forward

### GAP 8: No STIX 2.1 Export as Canonical Format
**Spec requires:** JSON-LD canonical with STIX 2.1 projection
**Current:** STIX export endpoint exists but no JSON-LD
**Action:** Ensure STIX export includes all entity types; JSON-LD is aspirational

### GAP 9: No VirusTotal/MalwareBazaar Graph Relationships
**Spec requires:** Related files/URLs/domains from VT, family relationships
**Current:** Enrichment providers configured but no graph relationship extraction
**Action:** Wire VT enrichment to auto-create relationship claims

### GAP 10: No Academic Paper Index
**Spec requires:** Crossref/Semantic Scholar metadata, DOI, citation trails
**Current:** Nothing
**Action:** Import key CTI papers via SearXNG + academic search

### GAP 11: No Incremental Freshness Tracking
**Spec requires:** ETag, Last-Modified, commit SHAs, STIX modified timestamps
**Current:** Feed poller runs but no change detection metadata
**Action:** Add change tracking to feed poller (partially implemented via Alembic)

### GAP 12: No Quality Metrics
**Spec requires:** Source coverage, extraction precision, freshness lag, dedupe collision rate
**Current:** Nothing measured
**Action:** Add metrics endpoint and monitoring

### GAP 13: Missing Source Feeds
**Spec lists but we lack:**
- GitHub Advisory sync (have NVD/KEV, missing GHSA)
- ANY.RUN / Hybrid Analysis sandbox output
- CISA advisories (not just KEV)
- Microsoft Security Response Center
- Google Threat Intelligence
- Cisco Talos
- Academic paper indexes

### GAP 14: No Sandbox/Payload Quarantine
**Spec requires:** Isolated sample storage, no raw binaries in search index
**Current:** No sample storage at all
**Action:** Design quarantine path (data/quarantine/)

### GAP 15: Missing MCP Tools
**Spec requires:** search_cti, get_record, get_entity_graph, get_sample_analysis, get_function_map, compare_sysmon_configs
**Current:** 59 tools but missing: compare_sysmon_configs, get_function_map, search_cti (have search_knowledge)
**Action:** Add missing tools where data exists
