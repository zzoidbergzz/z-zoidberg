# context_packs.md — Security Knowledge Context Packs

## Blue team SOC triage starter pack

**Purpose:** Ground first-response reasoning for alerts in endpoint, identity, cloud, and network contexts.
**Audience:** SOC analysts, junior blue teamers, shift leads.
**2k variant:** CSF risk vocabulary, SP 800-61r3 response framing, Sysmon caveat that telemetry is not analytics, Defender for Endpoint role, KEV/EPSS reminders.
**8k variant:** Add Windows process telemetry, Sysmon event families, process/network/DNS correlation, Sentinel role, identity context with Entra.
**32k variant:** Add ATT&CK technique mapping, D3FEND countermeasure vocabulary, application and cloud pivots, false-positive handling, case-quality questions.
**Required source set:** NIST CSF 2.0, SP 800-61r3, Sysmon, Defender for Endpoint, Sentinel, Entra, ATT&CK, D3FEND.
**Required facts:** `fact_csf20_definition`, `fact_sp80061r3_ir_across_csf`, `fact_sysmon_no_analysis`, `fact_sysmon_process_create`, `fact_mde_capabilities`, `fact_sentinel_cloud_native_siem`.
**Required entities:** `ent_framework_nist_csf_20`, `ent_framework_nist_sp_800_61_r3`, `ent_tool_sysmon`, `ent_product_defender_endpoint`, `ent_product_sentinel`, `ent_product_entra`.
**Retrieval queries:** `windows process creation triage`, `sysmon event 1 investigation`, `SOC triage checklist`, `alert response CSF`, `KEV exploitation urgency`.

---

## Vulnerability management prioritisation pack

**Purpose:** Help analysts reason about CVE severity, exploitation likelihood, and actionable remediation priority without conflating CVSS with risk.
**Audience:** Vulnerability management teams, risk owners, CTI analysts.
**2k variant:** CVE/NVD relationship, CVSS severity caveat, KEV urgency signal, EPSS probability role.
**8k variant:** Add SSVC decision-tree framing, CVSS v4.0 metric groups, EPSS thresholds for queuing, KEV binding directive timeline.
**32k variant:** Add asset criticality overlays, business-exposure factors, SLA calculation examples, patch-wave prioritisation patterns.
**Required source set:** CVE, NVD, CVSS v4.0, EPSS, KEV, SSVC.
**Required facts:** `fact_nvd_enrichment`, `fact_cvss_metric_groups`, `fact_epss_probability`, `fact_kev_prioritization_input`, `fact_ssvc_action_model`.
**Required entities:** `ent_framework_cve`, `ent_product_nvd`, `ent_framework_cvss_v40`, `ent_framework_epss`, `ent_catalog_kev`, `ent_framework_ssvc`.
**Retrieval queries:** `vulnerability prioritisation KEV EPSS CVSS`, `SSVC decision tree`, `CVE NVD enrichment`, `exploitation likelihood scoring`.

---

## CTI sharing and exchange pack

**Purpose:** Orient CTI producers and consumers in STIX/TAXII mechanics and the CSAF/VEX advisory ecosystem.
**Audience:** CTI analysts, platform engineers, detection engineers.
**2k variant:** STIX 2.1 object model basics, TAXII HTTPS transport, CSAF VEX profile overview.
**8k variant:** Add STIX relationship types, TAXII collections/channels, CSAF advisory versioning, OSV schema for package vulns.
**32k variant:** Add MISP mapping, threat actor attribution patterns, STIX indicator lifecycle, integration patterns with SIEM/SOAR.
**Required source set:** STIX 2.1, TAXII 2.1, CSAF 2.1, OSV schema.
**Required facts:** `fact_stix_machine_readable_cti`, `fact_taxii_https`, `fact_csaf_vex_profile`, `fact_osv_precise_versions`.
**Required entities:** `ent_framework_stix_21`, `ent_framework_taxii_21`, `ent_framework_csaf_21`, `ent_framework_osv_schema`.
**Retrieval queries:** `STIX TAXII CTI exchange`, `CSAF VEX advisory`, `machine-readable threat intel`, `OSV package vulnerability`.

---

## Application security verification pack

**Purpose:** Provide a stable technical control vocabulary for application security assessments, testing, and reporting.
**Audience:** AppSec engineers, pentesters, secure developers.
**2k variant:** ASVS level structure and use case, WSTG testing category overview, API Security Top 10 key risks.
**8k variant:** Add ASVS control-requirement mapping, WSTG test case structures, BOLA/BFLA/SSRF API risk patterns.
**32k variant:** Add integration testing patterns, false-positive guidance, finding-to-requirement mapping templates.
**Required source set:** OWASP ASVS 5.0, OWASP WSTG, OWASP API Security Top 10 2023.
**Required facts:** `fact_asvs_testing_basis`, `fact_wstg_comprehensive`, `fact_api_top10_2023_authz`.
**Required entities:** `ent_framework_asvs_50`, `ent_framework_wstg`, `ent_framework_api_top10_2023`.
**Retrieval queries:** `ASVS verification requirements`, `WSTG testing methodology`, `API security top 10 authorisation`, `BOLA broken object level`.

---

## Cloud-native security (Kubernetes) pack

**Purpose:** Connect Kubernetes security mechanisms to blue-team and cloud-security defensive practices.
**Audience:** Cloud security engineers, platform engineers, blue team.
**2k variant:** Kubernetes audit log as security telemetry, control-plane access risk, secrets handling basics.
**8k variant:** Add admission control, network policy, RBAC least-privilege patterns, audit log event structure.
**32k variant:** Add runtime threat detection patterns, container escape scenarios (defensive framing), Sentinel ingestion of K8s audit logs.
**Required source set:** Kubernetes security documentation, Microsoft Sentinel.
**Required facts:** `fact_k8s_audit_logs`, `fact_sentinel_cloud_native_siem`.
**Required entities:** `ent_concept_kubernetes_audit_logging`, `ent_product_sentinel`.
**Retrieval queries:** `kubernetes audit logs security`, `cloud-native detection`, `k8s RBAC admission control`, `container security telemetry`.
