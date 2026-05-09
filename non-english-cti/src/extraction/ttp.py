"""TTP mapping to MITRE ATT&CK techniques."""

from __future__ import annotations
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Common ATT&CK technique patterns and their IDs
# This is a simplified mapping for common CTI patterns
ATTACK_PATTERNS = {
    # Initial Access
    r"(?:spear\s*phishing|phishing\s*email|lure\s*document)": {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    r"(?:watering\s*hole|drive[\s-]by\s*download)": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
    r"(?:supply\s*chain|third[\s-]party\s*software)": {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access"},

    # Execution
    r"(?:powershell|ps1\s*script)": {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    r"(?:command\s*line|cmd\.exe|batch\s*file)": {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
    r"(?:wmi|wmic)": {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution"},
    r"(?:scheduled\s*task|cron|at\s*command)": {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
    r"(?:javascript|jscript|vbscript)": {"id": "T1059.005", "name": "Visual Basic", "tactic": "Execution"},
    r"(?:python\s*script|\.py)": {"id": "T1059.006", "name": "Python", "tactic": "Execution"},

    # Persistence
    r"(?:registry\s*run\s*key|startup\s*folder|autostart)": {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
    r"(?:scheduled\s*task.*persist|persistence.*task)": {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence"},
    r"(?:web\s*shell)": {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence"},
    r"(?:backdoor|back[\s-]?door)": {"id": "T1133", "name": "External Remote Services", "tactic": "Persistence"},

    # Privilege Escalation
    r"(?:privilege\s*escalat|uac\s*bypass|token\s*impersonat)": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    r"(?:credential\s*dump|mimikatz|lsass)": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},

    # Defense Evasion
    r"(?:process\s*inject|dll\s*inject|reflective\s*load)": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    r"(?:obfusc|encod|decrypt|xor\s*key)": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    r"(?:disable\s*(?:defender|antivirus|av|security)|tamper\s*protection)": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    r"(?:fileless|memory[\s-]only|in[\s-]memory)": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Defense Evasion"},
    r"(?:rootkit|bootkit|firmware)": {"id": "T1014", "name": "Rootkit", "tactic": "Defense Evasion"},

    # Credential Access
    r"(?:brute[\s-]?force|password\s*spray|credential\s*stuffing)": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    r"(?:keylog|keyboard\s*captur)": {"id": "T1056.001", "name": "Keylogging", "tactic": "Credential Access"},

    # Lateral Movement
    r"(?:lateral\s*movement|pass[\s-]?the[\s-]?hash|pth)": {"id": "T1550.002", "name": "Pass the Hash", "tactic": "Lateral Movement"},
    r"(?:remote\s*desktop|rdp|vnc)": {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    r"(?:psExec|psexec)": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},

    # Command and Control
    r"(?:c2|c&c|command[\s-]and[\s-]control|callback)": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    r"(?:dns\s*tunnel|dns\s*data\s*exfil)": {"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"},
    r"(?:https?[\s-]c2|tls[\s-]c2|encrypted[\s-]channel)": {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},

    # Exfiltration
    r"(?:exfiltrat|data\s*theft|data\s*transfer)": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},

    # Impact
    r"(?:ransomware|encrypt.*file|file.*encrypt)": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    r"(?:wiper|disk\s*wipe|data\s*destruct)": {"id": "T1488", "name": "Disk Structure Wipe", "tactic": "Impact"},
    r"(?:ddos|denial[\s-]of[\s-]service)": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    r"(?:deface|defacement)": {"id": "T1491", "name": "Defacement", "tactic": "Impact"},
}


def extract_ttps(text: str) -> list[dict]:
    """Extract MITRE ATT&CK TTPs from text using pattern matching.

    Returns list of dicts: {id, name, tactic, confidence, matched_text}
    """
    if not text:
        return []

    ttps = []
    text_lower = text.lower()

    for pattern, ttp_info in ATTACK_PATTERNS.items():
        matches = re.finditer(pattern, text_lower, re.IGNORECASE)
        for match in matches:
            ttp = {
                **ttp_info,
                "confidence": 0.7,  # Pattern match confidence
                "matched_text": match.group(),
            }
            # Avoid duplicate TTPs
            if not any(t["id"] == ttp["id"] for t in ttps):
                ttps.append(ttp)

    return ttps


# Known threat actor name patterns
ACTOR_PATTERNS = {
    r"\bAPT\s*(\d{1,2})\b": "APT-{0}",
    r"\bLazarus\s*Group\b": "Lazarus Group",
    r"\bKimsuky\b": "Kimsuky",
    r"\bSandworm\b": "Sandworm",
    r"\bFancy\s*Bear\b": "APT28",
    r"\bCozy\s*Bear\b": "APT29",
    r"\bWinnti\b": "Winnti Group",
    r"\bEquation\s*Group\b": "Equation Group",
    r"\bTurla\b": "Turla",
    r"\bFIN\d+\b": None,  # Keep as-is
    r"\bDarkHotel\b": "DarkHotel",
    r"\bOceanLotus\b": "OceanLotus",
    r"\bPatchwork\b": "Patchwork",
    r"\b(?:Dragonfly|Crouching\s*Yeti)\b": "Dragonfly",
    r"\b(?:FrostBite|VESTIBULE)\b": "FrostBite",
    r"\b(?:Hafnium)\b": "Hafnium",
}


def extract_actors(text: str) -> list[str]:
    """Extract threat actor names from text."""
    actors = []
    for pattern, name in ACTOR_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if name is None:
                actors.append(match)
            elif "{0}" in name:
                actors.append(name.format(match))
            else:
                actors.append(name)
    return sorted(set(actors))


# Known malware family patterns
MALWARE_PATTERNS = [
    r"\bEmotet\b", r"\bTrickBot\b", r"\bQakBot\b", r"\bDridex\b",
    r"\bCobalt\s*Strike\b", r"\bMetasploit\b", r"\bMimikatz\b",
    r"\bLockBit\b", r"\bConti\b", r"\bRyuk\b", r"\bBlackBasta\b",
    r"\bALPHV\b", r"\bCl0p\b", r"\bPlay\b", r"\bAkira\b",
    r"\bWannaCry\b", r"\bNotPetya\b", r"\bStuxnet\b",
    r"\bRemcos\b", r"\bAsyncRAT\b", r"\bCobalt\s*Strike\b",
    r"\bPlugX\b", r"\bPoisonIvy\b", r"\bGHIMBER\b",
    r"\bAgent\.Tesla\b", r"\bFormbook\b", r"\bRaccoon\b",
    r"\bRedLine\b", r"\bVidar\b", r"\bLumma\b",
]


def extract_malware(text: str) -> list[str]:
    """Extract malware family names from text."""
    malware = []
    for pattern in MALWARE_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        malware.extend(matches)
    return sorted(set(malware))
