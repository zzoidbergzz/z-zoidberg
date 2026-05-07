# sysinternals_pack.md — Microsoft Sysinternals Security Tools Pack

## Overview

Microsoft Sysinternals provides a suite of free Windows utilities widely used for endpoint security, incident response, and detection engineering. This pack covers the most security-relevant tools and their relationships to Windows telemetry and DFIR workflows.

---

## Sysmon (System Monitor)

**Entity ID:** `ent_tool_sysmon`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
**Purpose:** System service and device driver that logs process creation, network connections, DNS queries, file creation timestamps, driver loads, registry events, and more to the Windows event log (Microsoft-Windows-Sysmon/Operational).

**Key facts:**
- Sysmon collects high-fidelity telemetry but does NOT analyse events. Analysis is done by SIEMs, EDR tools, or investigators consuming the event log.
- Event ID 1 (Process Create) includes full command line, image hash, and parent process details — central to detection engineering and DFIR.
- Event ID 3 (Network Connection) is disabled by default; must be explicitly enabled in configuration.
- Event ID 22 (DNS Query) supports domain-based investigation.
- Sysmon events appear in the `Microsoft-Windows-Sysmon/Operational` channel.
- Complements but does not replace EDR telemetry (e.g., Microsoft Defender for Endpoint).

**Relationships:** emits → `ent_log_channel_sysmon_operational`; collects → `ent_data_component_process_creation`; complements → `ent_product_defender_endpoint`; relevant_to → `dfir`, `blue_team`.

---

## Process Monitor (Procmon)

**Entity ID:** `ent_tool_procmon`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
**Purpose:** Real-time monitoring of file system, registry, and process/thread activity. Essential for dynamic malware triage, persistence hunting, and troubleshooting.

**Key facts:**
- Captures real-time file, registry, process, and network activity with full stack traces.
- Not a persistent logging solution — requires an active session; data is not forwarded to a SIEM.
- Used alongside Autoruns to confirm whether observed persistence mechanisms trigger at runtime.

**Relationships:** investigates → `ent_tool_autoruns` (for persistence triage).

---

## Process Explorer

**Entity ID:** `ent_tool_process_explorer`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
**Purpose:** Advanced task manager showing parent-child process trees, DLL and handle details, and VirusTotal integration. Used for process triage and DLL injection analysis.

**Key facts:**
- Shows handles and DLLs loaded by each process — useful for DLL hijacking and injection detection.
- Provides process tree context that complements Sysmon Event ID 1 data.
- VirusTotal integration allows hash lookups directly from the tool.

**Relationships:** investigates → `ent_data_component_process_creation`.

---

## Autoruns

**Entity ID:** `ent_tool_autoruns`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
**Purpose:** Comprehensive autostart entry point (ASEP) enumeration — registry run keys, scheduled tasks, services, drivers, browser extensions, and more. Essential for persistence hunting.

**Key facts:**
- Most complete Windows autostart enumeration tool available.
- Colour-codes entries: red = not found, yellow = file not found, white = OK.
- VirusTotal integration flags known-bad hashes.
- Critical for persistence triage when combined with Procmon for confirmation.

---

## ProcDump

**Entity ID:** `ent_tool_procdump`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
**Purpose:** Command-line utility to create process memory dumps on demand, on trigger (CPU spike, exception), or on crash. Dumps are analysed with WinDbg or similar.

**Key facts:**
- Can capture LSASS dumps — a common attacker technique for credential harvesting; defenders use it to understand what attackers harvest.
- Supports mini, full, and custom dump formats.
- Complements WinDbg for post-incident memory forensics.

**Relationships:** complements → `ent_tool_windbg`.

---

## Sigcheck

**Entity ID:** `ent_tool_sigcheck`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck
**Purpose:** Verifies digital signatures on files and checks VirusTotal for known-bad hashes. Used to validate binary trust during triage.

**Key facts:**
- Can enumerate unsigned binaries in a directory — useful for finding dropped malware.
- VirusTotal integration for rapid hash reputation.
- Lightweight and scriptable for batch trust validation.

**Relationships:** investigates → `ent_data_component_process_creation` (binary trust validation).

---

## WinDbg

**Entity ID:** `ent_tool_windbg`
**Kind:** tool
**Platform:** Windows
**Download:** https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
**Purpose:** Microsoft's primary Windows debugger for kernel and user-mode debugging, crash dump analysis, and memory forensics.

**Key facts:**
- Used to analyse process memory dumps (captured by ProcDump or crash dumps).
- Supports kernel debugging for rootkit and driver-level investigation.
- Required for advanced malware analysis and crash root-cause analysis.

---

## Key data components (referenced)

**Process Creation (`ent_data_component_process_creation`):** Telemetry about new process launches including image path, command line, parent process, and user context. Central to detection of LOLBins, script interpreters, and lateral movement.

**Network Connection (`ent_data_component_network_connection`):** Outbound/inbound connection telemetry including remote IP, port, and initiating process. Key for C2 detection.

**DNS Query (`ent_data_component_dns_query`):** DNS resolution events including queried domain and response. Supports domain-based threat hunting.

**Sysmon Operational Log (`ent_log_channel_sysmon_operational`):** Windows event log channel `Microsoft-Windows-Sysmon/Operational`. Ingested by SIEMs and EDR platforms.

**Windows Security Event 4688 (`ent_event_id_4688`):** Native Windows Security log event for process creation. Less detailed than Sysmon Event 1 (no hash, limited command line unless enhanced auditing is enabled). Both are process-creation telemetry sources.
