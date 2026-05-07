# Deep Research Prompt: Cybersecurity Knowledge Seed Corpus

Use this prompt with Deep Research or an equivalent research agent when you want
to create a high-quality cybersecurity learning corpus for the Security
Knowledge service.

The goal is not just a report. The goal is a source-grounded, import-ready
knowledge package that can become data sources, parsed documents, evidence
spans, entities, claims, relationships, embeddings, and LLM context packs.

## Project Fit

This prompt is designed for a knowledge service with these concepts:

- Source records: canonical metadata for web pages, APIs, PDFs, books, docs, and local files.
- Raw objects: exact fetched or uploaded content, with hashes and content types.
- Parsed documents: normalized document-level records.
- Document sections: heading-aware chunks with order, page number, offsets, and content.
- Evidence: quote-sized text spans that support facts.
- Entities: canonical security objects such as techniques, tools, vulnerabilities, products, actors, malware, controls, detections, data sources, logs, events, frameworks, and procedures.
- Claims: atomic statements grounded in evidence.
- Relationships: typed links among entities, claims, controls, detections, logs, procedures, and learning objectives.
- Chunk embeddings: semantic retrieval chunks generated only after provenance, chunking, and evidence linkage are stable.

## Research Mission

You are a senior cybersecurity curriculum architect, CTI analyst, detection
engineer, vulnerability management lead, Windows internals practitioner, and
knowledge-graph data modeler.

Create a source-grounded cybersecurity base-knowledge corpus for LLM-assisted
learning and operational reasoning across:

- Blue team security operations
- Detection engineering
- Digital forensics and incident response
- Purple team emulation and validation
- Red team and penetration testing fundamentals
- Cyber threat intelligence
- Vulnerability management
- Exposure management
- Windows, Linux, identity, cloud, network, application, endpoint, and data security
- Microsoft Sysinternals, especially Sysmon and Windows telemetry workflows
- PDF and long-form document ingestion

The corpus must help an LLM form durable context, not memorize isolated trivia.
Prioritize concepts, relationships, evidence, procedures, observables,
constraints, caveats, and decision criteria.

## Safety Boundaries

Work in a defensive, educational, authorized-testing frame.

Allowed:

- Explain concepts, workflows, terminology, mappings, and defensive use.
- Describe offensive techniques at a high level when needed to understand detection, prevention, or authorized validation.
- Include lab-safe validation ideas and detection requirements.
- Include TTP mappings, observables, logs, controls, mitigations, and response actions.
- Include penetration testing methodology and reporting structure.

Do not include:

- Turnkey exploit chains against real targets.
- Malware code, payloads, persistence scripts, credential theft automation, stealth tooling, or evasion recipes.
- Instructions to bypass detection or security controls outside a clearly authorized lab.
- Live target reconnaissance instructions beyond safe, consent-based methodology.
- Secrets, leaked material, private exploit data, or copyrighted book excerpts beyond short cited snippets.

If a source contains offensive content, extract only the defensible knowledge:
preconditions, affected systems, observable behavior, detection logic,
mitigations, response, references, and risk.

## Source Strategy

Use authoritative, current, and stable sources first. Every claim must be
traceable to at least one source. Prefer primary sources over summaries.

### Tier 1 Sources

Security standards, frameworks, taxonomies, and official reference data:

- MITRE ATT&CK Enterprise, Mobile, ICS, mitigations, data sources, detections, software, groups, campaigns.
- MITRE D3FEND.
- MITRE CAPEC.
- MITRE CWE.
- CVE Program records.
- NIST NVD and NVD API 2.0.
- FIRST CVSS, EPSS, and related vulnerability scoring references.
- CISA Known Exploited Vulnerabilities catalog.
- CISA Cybersecurity Performance Goals.
- CISA advisories, alerts, malware analysis reports, and vulnerability guidance.
- NIST CSF 2.0.
- NIST SP 800-30, 800-37, 800-40, 800-53, 800-61, 800-83, 800-86, 800-92, 800-94, 800-115, 800-137, 800-160, 800-181.
- CIS Critical Security Controls.
- OWASP Top 10, ASVS, MASVS, WSTG, API Security Top 10, Cheat Sheet Series.
- OASIS STIX 2.1 and TAXII 2.1.
- CSAF, VEX, CycloneDX, SPDX, OSV, and GitHub Security Advisories.
- Microsoft Security documentation, Microsoft Defender documentation, Windows Event documentation, Windows auditing documentation, Microsoft Entra and Active Directory documentation.
- Microsoft Sysinternals documentation on Microsoft Learn.

### Tier 2 Sources

Vendor and open-source tooling documentation:

- Sigma specification and SigmaHQ rule repository documentation.
- YARA documentation.
- Suricata and Snort documentation.
- Zeek documentation.
- Elastic detection engineering docs.
- Splunk security content docs.
- OpenCTI documentation.
- MISP documentation.
- TheHive and Cortex documentation.
- Velociraptor documentation.
- Volatility documentation.
- osquery documentation.
- OpenTelemetry and security telemetry references where relevant.
- Kubernetes, Docker, AWS, Azure, Google Cloud, and GitHub security documentation.

### Tier 3 Sources

High-quality analytical sources used only when primary sources are insufficient:

- Incident reports from reputable vendors.
- Public postmortems.
- Security conference papers.
- Peer-reviewed or clearly sourced research.
- Vendor threat reports with transparent methodology.

### Source Exclusion Rules

Exclude or quarantine:

- Unsourced blog claims.
- Tool marketing pages without technical detail.
- Exploit PoC repositories unless the artifact is needed only for metadata and defensive context.
- Forums, social posts, paste sites, leaked chats, or private material.
- Sources with unclear redistribution terms unless only metadata is captured.

## Required Output Package

Produce these deliverables in one structured research package.

1. `research-report.md`
   - Executive summary.
   - Source methodology.
   - Curriculum and knowledge graph design.
   - Findings by domain.
   - Gaps, uncertainty, freshness risks, and recommended enrichment work.

2. `sources.jsonl`
   - One source record per line.
   - Include web pages, PDFs, APIs, official docs, Git repositories, and local/uploaded files.

3. `documents.jsonl`
   - One normalized document per line.
   - Include canonical source reference, content type, document date, version, license, and checksum if available.

4. `sections.jsonl`
   - One parsed section or chunk per line.
   - Include heading path, page number where available, offsets, token estimates, and content.

5. `entities.jsonl`
   - One normalized entity per line.
   - Include canonical name, kind, aliases, external refs, framework IDs, and properties.

6. `facts.jsonl`
   - One atomic claim per line.
   - Every fact must have evidence references and confidence.

7. `relationships.jsonl`
   - Typed links among entities, claims, techniques, controls, detections, logs, tools, vulnerabilities, procedures, roles, and learning units.

8. `learning_units.jsonl`
   - Structured learning objectives, prerequisites, explanations, labs, checks, and retrieval tags.

9. `context_packs.md`
   - Token-budgeted LLM context packs by role and task.

10. `sysinternals-pack.md`
    - A focused Microsoft Sysinternals knowledge pack.

11. `pdf-ingestion-playbook.md`
    - How to ingest PDFs safely and preserve page-level provenance.

12. `import-plan.md`
    - How to load the package into the Security Knowledge service.
    - Include required schema changes if the current service cannot ingest part of the package.

13. `quality-report.md`
    - Coverage matrix.
    - Source confidence matrix.
    - Conflict list.
    - Staleness and refresh schedule.
    - Data quality failures.

## JSONL Contracts

Use compact JSON objects, one object per line. Do not wrap JSONL in arrays.

### `sources.jsonl`

Required fields:

```json
{
  "source_id": "src_microsoft_sysinternals_sysmon",
  "title": "Sysmon - Sysinternals",
  "source_type": "microsoft_learn",
  "collection": "sysinternals",
  "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
  "canonical_url": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
  "publisher": "Microsoft",
  "author": ["Mark Russinovich", "Thomas Garnier"],
  "trust_tier": 1,
  "license": "verify",
  "terms_notes": "Official documentation. Check current Microsoft Learn terms before redistribution.",
  "refresh_cadence": "monthly",
  "last_verified": "YYYY-MM-DD",
  "acquisition_method": "web",
  "allowed_use": ["metadata", "short_quotes", "derived_facts", "citations"],
  "tags": ["windows", "endpoint", "telemetry", "sysinternals", "sysmon"]
}
```

### `documents.jsonl`

Required fields:

```json
{
  "document_id": "doc_sysmon_main",
  "source_id": "src_microsoft_sysinternals_sysmon",
  "title": "Sysmon - Sysinternals",
  "content_type": "text/html",
  "language": "en",
  "version": "v15.x or source-stated version",
  "published_at": "YYYY-MM-DD or null",
  "updated_at": "YYYY-MM-DD or null",
  "retrieved_at": "YYYY-MM-DD",
  "checksum_sha256": "if available",
  "word_count": 0,
  "metadata": {
    "product": "Sysmon",
    "platform": ["Windows", "Linux if documented"],
    "source_kind": "official_doc"
  }
}
```

### `sections.jsonl`

Required fields:

```json
{
  "section_id": "sec_sysmon_installation",
  "document_id": "doc_sysmon_main",
  "section_index": 12,
  "heading_path": ["Sysmon", "Installation"],
  "heading": "Installation",
  "page_number": null,
  "start_char": 10234,
  "end_char": 11890,
  "token_estimate": 430,
  "content": "Normalized section text...",
  "content_hash": "sha256",
  "chunk_policy": "heading-aware-600-900-tokens-overlap-80",
  "tables": [],
  "figures": [],
  "warnings": []
}
```

### `entities.jsonl`

Required fields:

```json
{
  "entity_id": "ent_tool_sysmon",
  "kind": "tool",
  "canonical_name": "Sysmon",
  "aliases": ["System Monitor"],
  "description": "One-sentence sourced description.",
  "external_refs": {
    "microsoft_learn": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "vendor": "Microsoft Sysinternals"
  },
  "properties": {
    "platforms": ["Windows"],
    "security_domains": ["endpoint_telemetry", "detection_engineering", "incident_response"],
    "role_relevance": ["blue_team", "purple_team", "dfir"],
    "freshness": "versioned"
  },
  "source_refs": ["src_microsoft_sysinternals_sysmon"]
}
```

Entity kinds to support:

- framework
- tactic
- technique
- subtechnique
- procedure
- data_source
- data_component
- log_source
- event_id
- detection
- control
- mitigation
- vulnerability
- weakness
- product
- vendor
- tool
- malware
- actor
- campaign
- report
- indicator
- attack_pattern
- asset_type
- identity_object
- cloud_service
- protocol
- file_artifact
- registry_artifact
- network_artifact
- command_artifact
- learning_objective
- lab
- assessment_item
- concept

### `facts.jsonl`

Required fields:

```json
{
  "fact_id": "fact_sysmon_network_connections",
  "statement": "Sysmon can log network connection activity to the Windows event log when configured to do so.",
  "fact_type": "capability",
  "subject": "ent_tool_sysmon",
  "predicate": "can_collect",
  "object": "ent_data_component_network_connection",
  "confidence": 0.95,
  "source_refs": ["src_microsoft_sysinternals_sysmon"],
  "evidence_refs": [
    {
      "document_id": "doc_sysmon_main",
      "section_id": "sec_sysmon_introduction",
      "quote": "Use a short quote only.",
      "page_number": null,
      "start_char": 0,
      "end_char": 0
    }
  ],
  "tags": ["sysmon", "windows", "endpoint", "telemetry"],
  "role_relevance": ["blue_team", "purple_team", "dfir"],
  "freshness": {
    "expires_after": "12 months",
    "refresh_reason": "tool versions and event schema can change"
  }
}
```

Fact types to use:

- definition
- capability
- limitation
- prerequisite
- procedure_step
- detection_logic
- telemetry_mapping
- control_mapping
- vulnerability_fact
- exploitation_context
- mitigation
- response_action
- investigation_question
- triage_criterion
- relationship_claim
- curriculum_claim
- caveat
- misconception_correction

### `relationships.jsonl`

Required fields:

```json
{
  "relationship_id": "rel_sysmon_collects_process_creation",
  "source_entity_id": "ent_tool_sysmon",
  "target_entity_id": "ent_data_component_process_creation",
  "kind": "collects",
  "confidence": 0.95,
  "source_refs": ["src_microsoft_sysinternals_sysmon"],
  "evidence_refs": ["fact_sysmon_process_creation"],
  "properties": {
    "platform": "windows",
    "use_cases": ["detection_engineering", "incident_response"]
  }
}
```

Relationship kinds to support:

- defines
- belongs_to
- includes
- uses
- detects
- mitigates
- prevents
- investigates
- collects
- emits
- observes
- maps_to
- prerequisite_for
- validates
- conflicts_with
- supersedes
- complements
- abuses
- hardens
- patches
- prioritizes
- enriches
- relevant_to_role
- taught_by
- assessed_by
- derived_from

### `learning_units.jsonl`

Required fields:

```json
{
  "learning_unit_id": "lu_blue_windows_process_telemetry_001",
  "title": "Understand Windows process creation telemetry",
  "level": "foundation",
  "roles": ["blue_team", "purple_team", "dfir"],
  "domains": ["windows", "endpoint", "detection_engineering"],
  "objectives": [
    "Explain why process creation telemetry is central to endpoint detection.",
    "Identify command line, parent process, image path, user, integrity level, and hash fields as investigation context."
  ],
  "prerequisites": ["lu_windows_process_model_001"],
  "source_refs": ["src_microsoft_sysinternals_sysmon", "src_mitre_attack_data_sources"],
  "entity_refs": ["ent_data_component_process_creation", "ent_tool_sysmon"],
  "fact_refs": ["fact_sysmon_process_creation"],
  "lab": {
    "type": "safe_local_lab",
    "description": "Review benign process creation events in a lab VM and map fields to investigation questions.",
    "no_live_targeting": true
  },
  "assessment": [
    {
      "question": "Which fields help distinguish normal administrative script execution from suspicious script execution?",
      "answer_key": "Parent process, command line, script path, user, frequency, signing, file origin, network context, and known baselines."
    }
  ],
  "retrieval_tags": ["windows_process_creation", "sysmon_event_1", "endpoint_telemetry"]
}
```

## Curriculum Architecture

Build the corpus as a progressive knowledge graph. Use five levels.

### Level 0: Orientation

Core mental models:

- Confidentiality, integrity, availability, safety, privacy, resilience.
- Threat, vulnerability, exposure, weakness, risk, impact, likelihood, control.
- Asset, identity, trust boundary, attack surface, blast radius.
- Telemetry, evidence, indicator, behavior, TTP, procedure.
- Prevention, detection, response, recovery, deception, deterrence.
- Alert, incident, case, finding, exception, false positive, false negative.
- Kill chain, intrusion lifecycle, ATT&CK tactic, technique, procedure.
- Intelligence cycle: requirements, collection, processing, analysis, dissemination, feedback.
- Vulnerability lifecycle: discovery, disclosure, publication, triage, remediation, verification, exception.

### Level 1: Foundations

Technology foundations:

- Networking: TCP/IP, UDP, DNS, HTTP, TLS, SMTP, SSH, SMB, Kerberos, LDAP, RDP, VPN, proxies.
- Operating systems: process model, memory, filesystems, permissions, services, drivers, logs.
- Windows: registry, event logs, services, scheduled tasks, WMI, PowerShell, Active Directory, Group Policy, Kerberos, NTLM, LSASS, Defender, auditing.
- Linux: processes, systemd, auditd, journald, syslog, file permissions, sudo, PAM, SSH, cron, containers.
- Identity: users, groups, service accounts, roles, tokens, sessions, federation, MFA, conditional access.
- Cloud: IAM, compute, storage, networking, logging, managed identity, security posture, cloud-native detections.
- Containers and Kubernetes: images, registries, pods, services, RBAC, admission control, audit logs.
- Applications: authentication, authorization, sessions, input validation, secrets, APIs, dependency risk.
- Cryptography for practitioners: hashing, signing, encryption, certificates, PKI, TLS, key management.

### Level 2: Security Operations

Blue team and DFIR:

- SOC operating model: intake, triage, investigation, escalation, response, closure, lessons learned.
- Alert triage: severity, confidence, asset criticality, business impact, prevalence, novelty, enrichment.
- Evidence handling: source reliability, chain of custody basics, timestamps, time zones, clock skew.
- Endpoint telemetry: process, image load, file, registry, network, DNS, driver, service, task, WMI, PowerShell, authentication.
- Network telemetry: DNS, proxy, firewall, NetFlow, Zeek, Suricata, TLS metadata, email telemetry.
- Identity telemetry: sign-ins, token events, privilege changes, group membership, service account usage.
- Cloud telemetry: control plane, data plane, workload, IAM, network flow, storage access, audit logs.
- SIEM: parsing, normalization, correlation, suppression, enrichment, case management.
- Detection engineering: hypothesis, data source, analytic, test set, tuning, deployment, drift monitoring.
- Incident response: preparation, identification, containment, eradication, recovery, post-incident activity.
- Forensics: acquisition, volatile data, disk artifacts, memory artifacts, timeline analysis, triage packages.
- Threat hunting: hypothesis-driven, baseline-driven, anomaly-driven, intel-driven, retrospective.

### Level 3: Offensive Understanding and Authorized Testing

Red team and pentest fundamentals:

- Rules of engagement, scope, authorization, safety, reporting, evidence management.
- Reconnaissance concepts: asset discovery, service discovery, public exposure, technology fingerprinting.
- Initial access categories: phishing concepts, exposed services, web vulnerabilities, supply chain, valid accounts.
- Execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, impact as ATT&CK concepts.
- Web testing methodology: OWASP WSTG, authentication, authorization, session management, injection, SSRF, deserialization, file upload, business logic.
- API testing methodology: auth, authorization, schema, object-level access, rate limits, mass assignment, injection, error handling.
- Active Directory assessment concepts: attack paths, delegation, local admin, Kerberos risks, group nesting, tiering.
- Cloud assessment concepts: IAM exposure, public storage, key leakage, metadata services, workload identity, logging gaps.
- Wireless and physical testing only as high-level methodology unless explicitly authorized.
- Exploit validation: safe reproduction, version checks, compensating controls, detection coverage, rollback plan.
- Reporting: finding anatomy, evidence, impact, likelihood, exploitability, remediation, retest.

### Level 4: Intelligence, Exposure, and Risk

CTI and vulnerability management:

- CTI requirements: PIRs, intelligence gaps, stakeholder mapping, collection plan.
- CTI tradecraft: source evaluation, confidence, competing hypotheses, bias, structured analytic techniques.
- CTI objects: actors, campaigns, malware, tools, infrastructure, vulnerabilities, TTPs, reports, sightings.
- STIX/TAXII modeling and interoperability.
- MISP and OpenCTI operational concepts.
- Indicator lifecycle: creation, validation, enrichment, expiration, sighting, revocation.
- Vulnerability sources: CVE, CNA advisories, NVD, vendor advisories, KEV, EPSS, exploit references, GHSA, OSV.
- Scoring and prioritization: CVSS, EPSS, KEV, SSVC, asset criticality, exposure, compensating controls, exploit maturity.
- Patch operations: ownership, SLAs, testing, exceptions, maintenance windows, verification, reporting.
- SBOM, VEX, CSAF, dependency risk, package ecosystems, transitive dependencies.
- Exposure management: external attack surface, internet exposure, identity exposure, cloud posture, exploit path.
- Metrics: mean time to triage, mean time to remediate, coverage, recurrence, accepted risk, backlog aging.

### Level 5: Advanced Integration

Cross-functional reasoning:

- Purple team planning: threat-informed objectives, emulation plan, data source requirements, detection hypotheses, validation, lessons learned.
- Control validation: map controls to TTPs, logs, tests, detection content, and response playbooks.
- Detection coverage: ATT&CK heatmaps, data source coverage, analytic quality, test coverage, alert fidelity.
- Security architecture: trust boundaries, segmentation, identity-first controls, secure logging, resilience.
- AI-assisted security: retrieval quality, source grounding, hallucination resistance, adversarial prompt risks, privacy.
- Knowledge graph operations: entity resolution, deduplication, provenance, contradiction handling, refresh cadence, deletion.

## Domain Coverage Requirements

For each domain below, produce:

- Definitions.
- Learning objectives.
- Core entities and relationships.
- Source list.
- Required telemetry.
- Common analyst questions.
- Defensive controls.
- Detection ideas.
- Lab-safe validation ideas.
- CTI/vulnerability links where relevant.
- Misconceptions and caveats.
- Importable facts and relationships.

### Blue Team

Cover:

- SOC workflow and case handling.
- Alert triage and enrichment.
- Detection engineering lifecycle.
- Threat hunting.
- SIEM and log pipelines.
- Endpoint detection.
- Network detection.
- Identity detection.
- Cloud detection.
- Email security.
- Incident response.
- DFIR triage.
- Malware analysis concepts.
- Ransomware response.
- Business email compromise response.
- Insider risk response.
- Data loss investigation.
- Metrics and quality assurance.

### Purple Team

Cover:

- Threat-informed defense.
- ATT&CK-based emulation planning.
- Control validation.
- Detection validation.
- Adversary emulation plans.
- Atomic tests and safety constraints.
- Exercise design.
- Scope and rollback.
- Evidence collection.
- Lessons learned.
- Coverage scoring.
- Engineering backlog creation.

### Red Team and Penetration Testing

Cover:

- Ethics and authorization.
- Scoping and ROE.
- Methodology.
- Reconnaissance concepts.
- Web app testing.
- API testing.
- Identity and Active Directory assessment.
- Cloud assessment.
- Container and Kubernetes assessment.
- Wireless and social engineering concepts at a high level.
- Exploit validation without weaponized steps.
- Reporting and retesting.
- Defensive mapping for every offensive concept.

### CTI

Cover:

- Intelligence requirements.
- Collection planning.
- Source evaluation.
- Confidence.
- Analytic tradecraft.
- Structured analytic techniques.
- STIX/TAXII.
- ATT&CK mappings.
- Diamond Model concepts.
- Kill Chain concepts.
- Campaign tracking.
- Malware and tool tracking.
- Infrastructure tracking.
- Indicator lifecycle.
- Intelligence dissemination.
- Feedback loop.
- CTI-to-detection and CTI-to-vulnerability workflows.

### Vulnerability Management

Cover:

- Asset inventory.
- Vulnerability data sources.
- CVE, CWE, CPE, CVSS, EPSS, KEV, SSVC.
- Vendor advisories.
- Package advisories.
- SBOM, VEX, CSAF.
- Exposure and exploitability.
- Risk-based prioritization.
- Remediation ownership.
- Exceptions.
- Verification.
- Metrics.
- Executive reporting.
- Emergency response to exploited vulnerabilities.

### Windows and Microsoft Security

Cover:

- Windows internals needed for defenders.
- Windows event logs and channels.
- Advanced audit policy.
- PowerShell logging.
- WMI.
- Services.
- Scheduled tasks.
- Registry.
- Process and thread basics.
- Handles, DLLs, drivers.
- Authentication: Kerberos, NTLM, logon sessions, tokens.
- Active Directory security basics.
- Microsoft Defender and Defender for Endpoint concepts.
- Microsoft Sentinel concepts.
- Microsoft Entra ID security basics.
- Sysinternals tools and their defensive workflows.

### Linux, Network, Cloud, and Application Security

Cover:

- Linux audit/logging and common artifacts.
- Network protocols and visibility.
- IDS/IPS concepts.
- DNS security.
- TLS and certificate visibility.
- Email security.
- AWS, Azure, Google Cloud security foundations.
- Kubernetes security.
- Container image and runtime security.
- Web application security.
- API security.
- Secrets management.
- CI/CD and supply chain security.

## Microsoft Sysinternals Requirements

Build a dedicated Sysinternals corpus from official Microsoft Learn pages.

Minimum tools to include:

- Sysmon
- Process Monitor
- Process Explorer
- Autoruns
- TCPView
- PsExec
- PsTools suite
- Sigcheck
- Strings
- Handle
- ListDLLs
- ProcDump
- RAMMap
- VMMap
- AccessChk
- AccessEnum
- ShareEnum
- Streams
- SDelete
- LogonSessions
- PsLoggedOn
- PsLogList
- PsService
- PsInfo
- PsKill
- PsSuspend
- WinObj
- LiveKd
- ADExplorer
- Disk2vhd
- NotMyFault
- DebugView

For each tool, extract:

- Official name.
- Current version and publish/update date from the official source.
- Platform support.
- Purpose.
- Primary defensive use cases.
- Relevant Windows artifacts.
- Relevant logs or event IDs.
- Inputs and outputs.
- Common command-line options, summarized safely.
- Required privileges.
- Operational risks.
- Limitations.
- Abuse potential by attackers, described only to support detection and mitigation.
- Blue team workflows.
- DFIR workflows.
- Purple team validation workflows.
- Detection engineering mappings.
- ATT&CK technique and data source mappings.
- Related tools.
- Source URL and evidence spans.

### Sysmon Deep Dive

For Sysmon, produce a richer sub-corpus:

- Installation and configuration concepts.
- Event categories and event IDs.
- Configuration schema concepts.
- Include/exclude filtering concepts.
- Hashing, image, command line, parent-child process, network, DNS, registry, file, driver, image load, pipe, WMI, clipboard, file delete, process tampering, and archive-related telemetry where supported by the current version.
- Mapping from Sysmon events to ATT&CK data components.
- Mapping from Sysmon events to detection hypotheses.
- Safe lab validation ideas for common benign event generation.
- Configuration quality practices.
- False positive management.
- Log volume management.
- Collection architecture.
- EDR/SIEM integration.
- Caveats: Sysmon is telemetry, not prevention, and does not analyze events by itself.

Output specialized records:

- `ent_tool_sysmon`
- `ent_log_source_windows_event_log`
- `ent_log_channel_sysmon_operational`
- One entity per Sysmon event type.
- One fact per event capability.
- One relationship from event type to ATT&CK data component.
- One learning unit per major event family.

## PDF Ingestion Requirements

Assume PDFs may include NIST publications, vendor reports, whitepapers,
conference papers, books, and internal policy documents.

For each PDF source, capture:

- Original file name.
- Canonical URL or local path.
- SHA-256 checksum.
- Title.
- Authors.
- Publisher.
- Publication date.
- Version or revision.
- License or redistribution terms.
- Total pages.
- Language.
- Document type.
- Security classification or TLP if present.
- Table of contents if present.
- References and bibliography.

Parsing requirements:

- Preserve page numbers.
- Preserve heading hierarchy.
- Preserve paragraph order.
- Extract tables as structured rows where possible.
- Extract captions for figures.
- Mark OCR-derived text and OCR confidence.
- Mark missing, garbled, or image-only pages.
- Keep page-level and section-level hashes.
- Store exact evidence spans with page number and character offsets.
- Do not paraphrase evidence spans in evidence records.
- Normalize ligatures, broken line wraps, hyphenation, headers, footers, and page numbers.
- Remove boilerplate only when it is clearly repeated and keep a note that it was removed.
- Handle two-column layouts, footnotes, callout boxes, and appendices.

Chunking requirements:

- Prefer heading-aware chunks.
- Target 600-900 tokens per chunk.
- Use 50-100 token overlap only when a concept crosses chunk boundaries.
- Never split tables in a way that loses column meaning.
- Never split a definition from its term.
- Never split a procedure step from its warning.
- Keep page numbers and offsets on every chunk.
- Attach chunk tags: role, domain, concept, framework, technique, data source, control, tool.

PDF quality flags:

- `ocr_required`
- `ocr_low_confidence`
- `tables_detected`
- `figures_detected`
- `footnotes_detected`
- `citations_detected`
- `layout_complex`
- `copyright_limited`
- `needs_manual_review`

## LLM Learning Approach

Create knowledge for learning and reasoning, not a flat encyclopedia.

Every major topic should produce:

- `what_it_is`: concise definition.
- `why_it_matters`: operational relevance.
- `how_it_works`: mechanism.
- `where_seen`: logs, artifacts, controls, tools, reports.
- `how_to_detect`: telemetry and analytic ideas.
- `how_to_prevent_or_mitigate`: controls and tradeoffs.
- `how_to_validate_safely`: authorized lab or tabletop validation.
- `common_failures`: false assumptions, false positives, blind spots.
- `relationships`: links to frameworks, tools, techniques, controls, vulnerabilities.
- `questions_to_ask`: analyst prompts.
- `source_backing`: evidence refs.

For each role, produce progressive context packs:

### Blue Team Context Packs

- SOC triage fundamentals.
- Windows endpoint triage.
- Linux endpoint triage.
- Network alert triage.
- Identity alert triage.
- Cloud alert triage.
- Ransomware triage.
- BEC triage.
- Detection engineering starter pack.
- Threat hunting starter pack.
- DFIR starter pack.

### Purple Team Context Packs

- ATT&CK mapping starter pack.
- Emulation planning starter pack.
- Detection validation starter pack.
- Control validation starter pack.
- Evidence collection starter pack.
- Lessons learned and backlog starter pack.

### Red Team and Pentest Context Packs

- Authorization and scoping starter pack.
- Web testing methodology starter pack.
- API testing methodology starter pack.
- AD assessment concept pack.
- Cloud assessment concept pack.
- Reporting and remediation pack.
- Defensive mapping pack.

### CTI Context Packs

- Intelligence requirements pack.
- Source evaluation pack.
- ATT&CK mapping pack.
- Actor/campaign tracking pack.
- Indicator lifecycle pack.
- STIX/TAXII pack.
- CTI-to-detection pack.
- CTI-to-vulnerability pack.

### Vulnerability Management Context Packs

- Vulnerability source pack.
- CVSS/EPSS/KEV/SSVC pack.
- Asset-context prioritization pack.
- Emergency remediation pack.
- SBOM/VEX/CSAF pack.
- Metrics and executive reporting pack.

Each context pack must include:

- Purpose.
- Audience.
- Token budget: 2k, 8k, and 32k variants.
- Required source set.
- Required facts.
- Required entities.
- Required relationships.
- Retrieval queries.
- Things the LLM must not assume.
- Freshness warnings.

## Knowledge Graph Mappings

Map across these frameworks and schemas where applicable:

- ATT&CK tactic, technique, subtechnique, mitigation, data source, data component.
- D3FEND defensive technique.
- NIST CSF 2.0 function, category, subcategory.
- NIST SP 800-53 control family and control.
- CIS Control and safeguard.
- CWE weakness.
- CAPEC attack pattern.
- CVE/NVD vulnerability.
- CVSS vector.
- EPSS probability.
- KEV exploited status.
- SSVC decision points.
- OWASP category.
- STIX object type.
- MISP object/attribute/galaxy type.
- Sigma logsource and detection fields.
- YARA rule metadata where relevant.
- Windows Event Log channel, provider, and event ID.
- Sysmon event ID and field names.
- Cloud log source and event name.

## Detection Engineering Requirements

For each detection topic:

- State the detection hypothesis.
- Identify data sources and data components.
- Identify required fields.
- Identify optional enrichment.
- Identify likely false positives.
- Identify known blind spots.
- Identify ATT&CK mappings.
- Identify severity factors.
- Identify response playbook links.
- Provide Sigma-like pseudologic when safe.
- Do not output deployable detection content unless it is generic and defensive.
- Mark required lab validation data.

Detection record shape:

```json
{
  "detection_id": "det_windows_suspicious_encoded_powershell_concept",
  "title": "Suspicious encoded PowerShell command concept",
  "hypothesis": "Encoded PowerShell command lines can indicate obfuscation or automation and should be evaluated with parent process, user, script source, and baseline context.",
  "data_sources": ["Process: Process Creation", "Command: Command Execution"],
  "required_fields": ["process_name", "command_line", "parent_process_name", "user", "host", "timestamp"],
  "logic_summary": "Look for PowerShell execution with encoded-command style arguments, then suppress known administrative automation after validation.",
  "false_positive_sources": ["administration scripts", "software deployment tools"],
  "blind_spots": ["missing command-line logging", "renamed binaries", "script block logging disabled"],
  "attck_refs": ["T1059.001"],
  "sysinternals_refs": ["Sysmon process creation telemetry"],
  "response_questions": ["Who ran it?", "What spawned it?", "Was it expected on this host?", "Did it make network connections?"],
  "safety": "conceptual_defensive_detection"
}
```

## Vulnerability Management Requirements

For vulnerability topics:

- Explain CVE, CWE, CPE, CVSS, EPSS, KEV, SSVC, VEX, CSAF, SBOM, OSV, GHSA.
- Explain their relationships and limitations.
- Produce decision trees for prioritization.
- Include exploit-in-the-wild handling.
- Include compensating controls and exceptions.
- Include verification and retest.
- Include executive reporting concepts.

Do not treat CVSS alone as risk. Always combine:

- Asset criticality.
- Exposure.
- Reachability.
- Known exploitation.
- Exploit maturity.
- Control coverage.
- Business impact.
- Patch availability.
- Operational constraints.
- Threat relevance.

## CTI Requirements

For CTI topics:

- Separate data, information, intelligence, and assessment.
- Mark source reliability and information credibility.
- Capture confidence and reasoning.
- Avoid over-attribution.
- Preserve uncertainty.
- Link TTPs to procedures and evidence.
- Link indicators to lifecycle states and expiration.
- Link vulnerabilities to campaigns only when sourced.
- Link intelligence requirements to collection and dissemination.
- Include stakeholder-specific output examples.

Analytic standards:

- Distinguish fact from assessment.
- Include alternative explanations.
- Mark collection gaps.
- Mark stale indicators.
- Mark confidence.
- Do not infer actor attribution from a single weak indicator.

## Red/Pentest Knowledge Requirements

For offensive concepts, create defensive learning records:

- Methodology.
- Preconditions.
- Target class.
- Risk.
- Observable behavior.
- Logs and artifacts.
- Controls that prevent or limit it.
- Detection opportunities.
- Safe validation method.
- Reporting guidance.

Do not provide:

- Live exploitation commands.
- Credential capture workflows.
- Persistence payloads.
- Stealth guidance.
- Bypass instructions.
- Automated attack chains.

## Data Quality Rules

Apply these rules to every output:

- Every fact has at least one evidence reference.
- Every evidence quote is short and exact.
- Every source has publisher, URL/path, trust tier, and retrieval date.
- Every framework mapping has a source.
- Every generated relationship has a reason.
- Mark conflicts instead of silently choosing one side.
- Mark stale facts and refresh cadence.
- Mark "unknown" instead of guessing.
- Prefer canonical names.
- Keep aliases.
- Deduplicate by external refs before names.
- Do not merge entities destructively.
- Keep vendor-specific fields in `properties`.
- Avoid normative claims unless the source is a standard or official guidance.
- Separate "is" claims from "should" claims.
- Separate "can" from "does".
- Separate "documented capability" from "observed in the wild".

## Coverage Matrix

Produce a coverage matrix with rows for domains and columns:

- Definitions
- Framework mappings
- Tools
- Telemetry
- Detection
- Response
- Controls
- Labs
- Vulnerability links
- CTI links
- Sysinternals links
- PDF sources
- Machine-readable facts
- Confidence
- Freshness risk

Domains:

- Security fundamentals
- Networking
- Windows
- Linux
- Active Directory
- Cloud
- Kubernetes
- Web applications
- APIs
- Endpoint security
- Network security
- Identity security
- Email security
- DFIR
- Detection engineering
- Threat hunting
- Purple team
- Red team
- Penetration testing
- CTI
- Vulnerability management
- Supply chain security
- Malware analysis concepts
- Ransomware
- Data security
- Governance and risk

## Source Seed List

Use this as the first pass. Expand only with high-quality sources.

### Microsoft Sysinternals

- https://learn.microsoft.com/en-us/sysinternals/
- https://learn.microsoft.com/en-us/sysinternals/downloads/
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
- https://learn.microsoft.com/en-us/sysinternals/downloads/pstools
- https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview
- https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck
- https://learn.microsoft.com/en-us/sysinternals/downloads/handle
- https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls
- https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- https://learn.microsoft.com/en-us/sysinternals/downloads/strings
- https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
- https://learn.microsoft.com/en-us/sysinternals/downloads/accessenum
- https://learn.microsoft.com/en-us/sysinternals/downloads/shareenum
- https://learn.microsoft.com/en-us/sysinternals/downloads/streams
- https://learn.microsoft.com/en-us/sysinternals/downloads/logonsessions
- https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon
- https://learn.microsoft.com/en-us/sysinternals/downloads/psloglist
- https://learn.microsoft.com/en-us/sysinternals/downloads/psservice
- https://learn.microsoft.com/en-us/sysinternals/downloads/winobj
- https://learn.microsoft.com/en-us/sysinternals/downloads/livekd

### Core Frameworks and Reference Data

- https://attack.mitre.org/
- https://d3fend.mitre.org/
- https://capec.mitre.org/
- https://cwe.mitre.org/
- https://www.cve.org/
- https://nvd.nist.gov/
- https://nvd.nist.gov/developers/vulnerabilities
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.first.org/cvss/
- https://www.first.org/epss/
- https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- https://www.nist.gov/cyberframework
- https://csrc.nist.gov/publications/sp
- https://www.cisecurity.org/controls
- https://owasp.org/www-project-top-ten/
- https://owasp.org/www-project-application-security-verification-standard/
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/www-project-api-security/
- https://oasis-open.github.io/cti-documentation/

### Detection, Telemetry, and Security Tooling

- https://sigmahq.io/
- https://github.com/SigmaHQ/sigma
- https://yara.readthedocs.io/
- https://docs.suricata.io/
- https://docs.zeek.org/
- https://osquery.readthedocs.io/
- https://docs.velociraptor.app/
- https://volatility3.readthedocs.io/
- https://docs.opencti.io/
- https://www.misp-project.org/documentation/
- https://thehive-project.org/

### Vendor and Platform Security Docs

- https://learn.microsoft.com/en-us/windows/security/
- https://learn.microsoft.com/en-us/defender/
- https://learn.microsoft.com/en-us/azure/sentinel/
- https://learn.microsoft.com/en-us/entra/
- https://docs.aws.amazon.com/security/
- https://cloud.google.com/security
- https://learn.microsoft.com/en-us/azure/security/
- https://kubernetes.io/docs/concepts/security/
- https://docs.docker.com/security/
- https://docs.github.com/en/code-security

## Research Process

Follow this sequence:

1. Build the source inventory.
2. Classify source trust, license, freshness, and acquisition method.
3. Create a curriculum ontology and entity taxonomy.
4. Ingest Tier 1 source metadata.
5. Extract authoritative definitions.
6. Extract framework mappings.
7. Extract telemetry and data source mappings.
8. Extract Sysinternals tool knowledge.
9. Extract vulnerability management source relationships.
10. Extract CTI workflow and object relationships.
11. Extract blue-team and DFIR workflows.
12. Extract purple-team validation workflows.
13. Extract red/pentest methodology only in defensive, authorized terms.
14. Produce atomic facts.
15. Link every fact to evidence.
16. Create relationships.
17. Create learning units.
18. Create context packs.
19. Produce import plan.
20. Produce quality report.

## Conflict and Uncertainty Handling

When sources disagree:

- Preserve both claims.
- Add `conflicts_with` relationships.
- Explain the disagreement.
- Prefer official current docs for product capabilities.
- Prefer standards for definitions.
- Prefer current vulnerability records for vulnerability metadata.
- Mark stale or superseded sources.

When information is missing:

- Use `unknown`.
- Add a gap item.
- Add a recommended source or enrichment provider.
- Do not infer.

## Import Plan Requirements

Assess whether the target Security Knowledge service can ingest the package as-is.

Check for these needed features:

- URL ingestion.
- Local file ingestion.
- PDF ingestion.
- HTML parsing.
- Markdown parsing.
- JSON/API ingestion.
- Source registry.
- Raw object storage.
- Parsed document storage.
- Section chunking.
- Evidence span storage.
- Entity upsert.
- Claim upsert.
- Relationship upsert.
- Embedding generation.
- Semantic search.
- Context pack API.
- Source policy allowlist.
- Tenant scoping.
- Refresh jobs.
- Provenance and audit events.

For each missing feature, output:

- Feature name.
- Why it is needed.
- Minimal implementation.
- Data model impact.
- API impact.
- Worker impact.
- Tests required.
- Priority.

## Expected Finding for This Repository

Assume the repository may already have partial scaffolding but may not yet have
full ingestion. Validate this during implementation.

Expected likely state:

- Entity, claim, source, document, evidence, job, and embedding models may exist.
- Manual entity and claim APIs may exist.
- MITRE ATT&CK and a small reverse-shell corpus may have seeders.
- URL ingestion may create jobs.
- The worker may not yet fetch, parse, chunk, extract, embed, or write evidence.
- PDF ingestion may not exist.
- Context pack output may be documented but not implemented.
- Source policy may need Microsoft Learn, MITRE, NIST, CISA, FIRST, OWASP, OASIS, and tooling domains added.
- Schema and migrations may need alignment before large ingestion.

The final report must state clearly what is usable now and what needs enrichment.

## Final Answer Format

Return a concise top-level summary first:

1. Best source combination.
2. Best ingestion order.
3. Whether the target project can use it today.
4. Required enrichment work.
5. Major risks.

Then provide the full deliverable package.

## Output Format and Continuation Protocol

The output must not be a single unbounded wall of text. Use a manifest-first,
multi-part format so long outputs can continue cleanly without losing structure.

### Start With `MANIFEST.md`

Begin by outputting:

```markdown
# MANIFEST.md

Package: cybersecurity-knowledge-seed-corpus
Generated: YYYY-MM-DD
Part: 1 of N

## Artifacts

- research-report.md
- sources.jsonl
- documents.jsonl
- sections.jsonl
- entities.jsonl
- facts.jsonl
- relationships.jsonl
- learning_units.jsonl
- context_packs.md
- sysinternals-pack.md
- pdf-ingestion-playbook.md
- import-plan.md
- quality-report.md

## Completion Status

| Artifact | Status | Rows/Sections | Notes |
| --- | --- | ---: | --- |
| research-report.md | pending | 0 | |
```

Update the completion table at the end of every part.

### Artifact Boundaries

Wrap each artifact with clear boundaries:

```text
--- BEGIN ARTIFACT: sources.jsonl ---
{"source_id":"src_example","title":"Example","source_type":"official_doc"}
--- END ARTIFACT: sources.jsonl ---
```

For JSONL artifacts:

- Emit one valid JSON object per line.
- Do not wrap JSONL in markdown code fences unless the interface requires it.
- Do not split a JSON object across parts.
- If space is running low, stop before the next JSON object.
- End the part with a continuation marker.

### Continuation Marker

If the answer is too long, stop cleanly with:

```text
--- CONTINUE FROM: <artifact-name> line <next-line-number> ---
```

When continuing, start with:

```text
--- RESUMING FROM: <artifact-name> line <line-number> ---
```

Then continue with the next complete JSONL object or markdown section.

### Size Controls

To avoid truncation:

- Put the summary and manifest in Part 1.
- Put large JSONL artifacts in separate parts.
- Prefer concise records over prose duplication.
- Use stable IDs so later parts can reference earlier artifacts.
- Keep evidence quotes short.
- If the interface has a token limit, produce representative high-confidence seed records first, then add expansion batches.
- Never omit the import plan and quality report; if needed, make them concise in the first pass and mark expansion work.

### Minimum Viable First Pass

If a full corpus will exceed the output limit, produce this first:

1. `MANIFEST.md`
2. `research-report.md`
3. `sources.jsonl` with the top 50 highest-value sources
4. `entities.jsonl` with the top 150 canonical entities
5. `facts.jsonl` with the top 250 high-confidence facts
6. `relationships.jsonl` with the top 250 relationships
7. `learning_units.jsonl` with the core learning path
8. `import-plan.md`
9. `quality-report.md`

Then continue with expansion batches:

- Batch A: Microsoft Sysinternals and Sysmon.
- Batch B: ATT&CK, D3FEND, CAPEC, CWE mappings.
- Batch C: blue team, DFIR, detection engineering.
- Batch D: CTI and vulnerability management.
- Batch E: purple team, red team, and penetration testing methodology.
- Batch F: PDF and long-form source expansions.

## Best Initial Ingestion Order

Use this staged order to keep the knowledge graph coherent:

1. Security vocabulary and source registry.
2. NIST CSF, CIS Controls, and core risk/controls concepts.
3. ATT&CK tactics, techniques, mitigations, data sources, and data components.
4. Windows telemetry and Sysinternals, starting with Sysmon.
5. Detection engineering and Sigma concepts.
6. DFIR and incident response.
7. Vulnerability management: CVE, CWE, CPE, CVSS, EPSS, KEV, SSVC, SBOM, VEX, CSAF.
8. CTI: STIX/TAXII, MISP, OpenCTI, intelligence cycle, confidence.
9. Purple team validation and control testing.
10. Red team and penetration testing methodology with defensive mappings.
11. Cloud, Kubernetes, application, API, identity, and supply chain expansions.
12. PDFs and long-form reports, once PDF provenance handling is ready.

## Success Criteria

The research succeeds only if:

- A defender can ask "what should I know about this alert, tool, event, vulnerability, actor, or technique?" and get grounded context.
- A learner can progress from fundamentals to role-specific practice.
- A detection engineer can map a technique to data sources, fields, logic, false positives, and validation.
- A CTI analyst can map sources to actors, campaigns, TTPs, indicators, confidence, and collection gaps.
- A vulnerability manager can prioritize using exploitability, exposure, asset criticality, and control context.
- A red/pentest learner gets methodology, ethics, reporting, and defensive mappings without unsafe operational detail.
- Every material claim has evidence.
- Every source can be refreshed or retired.
- The import package can be loaded without losing provenance.
