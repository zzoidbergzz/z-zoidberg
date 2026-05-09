#!/usr/bin/env python3
"""Scan offensive security repos for CTI-relevant data.

Extracts:
- File hashes (SHA256) for binaries, scripts, configs
- IOCs (IPs, domains, URLs, email addresses)
- CVE references
- MITRE ATT&CK technique IDs
- Known malware/ransomware family names
- C2 framework indicators (beacon configs, callback patterns)
- YARA-signature patterns for sigma rule matching

Outputs: JSON for ingestion into z.je SK platform as entities.
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# --- Patterns ---
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
ATTACK_TECH_RE = re.compile(r'T\d{4}(?:\.\d{3})?')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|cc|me|tk|ml|ga|cf|gq)\b', re.IGNORECASE)
URL_RE = re.compile(r'https?://[^\s<>"\'\)]+', re.IGNORECASE)
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')

# File extensions worth hashing
HASH_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.bin', '.sh', '.py', '.ps1', '.bat', '.cmd',
    '.vbs', '.js', '.vba', '.doc', '.docm', '.xlsm', '.pptm', '.pdf',
    '.lnk', '.hta', '.sct', '.wsf', '.inf', '.reg', '.msp', '.msi',
    '.elf', '.so', '.deb', '.rpm', '.yml', '.yaml', '.json', '.xml',
    '.conf', '.cfg', '.config', '.rc', '.toml',
}

# Skip directories
SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.venv', 'venv',
             'vendor', 'dist', 'build', '.idea', '.vscode'}

# Known ransomware families (for pattern matching)
RANSOMWARE_FAMILIES = [
    "lockbit", "blackcat", "alphv", "conti", "ryuk", "revil", "sodinokibi",
    "maze", "egregor", "doppelpaymer", "clop", "royal", "black basta",
    "play", "vice society", "lockergoga", "wannacry", "petya", "notpetya",
    "cerber", "cryptolocker", "teslacrypt", "dharma", "phobos", "gandcrab",
    "trickbot", "emotet", "qakbot", "icedid", "bazarloader", "cobaltstrike",
    "ragnar", "ragnarok", "avoslocker", "hives", "blackmatter", "darkside",
    "babuk", "kaseya", "mediabkp", "spora", "jaff", "stampado",
]

# Known C2 indicators
C2_INDICATORS = [
    "beacon", "callback", "c2", "command.and.control", "cnc", "implant",
    "payload", "stager", "listener", "handler", "agent", "session",
    "shellcode", "injection", "evasion", "lateral", "pivot", "proxy",
    "socks", "tunnel", "reverse_shell", "bind_shell", "meterpreter",
    "sliver", "mythic", "havoc", "empire", "covenant", "merlin",
    "brute-ratel", "cobalt", "posh", "powerfun", "powercat",
]


def should_hash(path: Path) -> bool:
    """Check if file should be hashed."""
    if path.stat().st_size > 10_000_000:  # Skip >10MB
        return False
    return path.suffix.lower() in HASH_EXTENSIONS


def compute_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
    except (PermissionError, OSError):
        return ""
    return h.hexdigest()


def extract_patterns(text: str) -> dict:
    """Extract IOCs, CVEs, ATT&CK IDs from text."""
    return {
        "cves": list(set(CVE_RE.findall(text))),
        "attack_techniques": list(set(ATTACK_TECH_RE.findall(text))),
        "ipv4": [ip for ip in set(IPV4_RE.findall(text))
                 if not ip.startswith(("0.", "127.", "10.", "192.168.", "172.16.", "172.17.",
                                       "172.18.", "172.19.", "172.2", "172.3",
                                       "255.255.255", "224.", "239."))],
        "domains": list(set(DOMAIN_RE.findall(text))),
        "urls": [u for u in set(URL_RE.findall(text))
                 if not any(x in u for x in ("github.com", "youtube.com", "wikipedia.org",
                                              "stackoverflow.com", "microsoft.com", "python.org"))],
        "emails": list(set(EMAIL_RE.findall(text))),
        "sha256_hashes": list(set(SHA256_RE.findall(text))),
        "sha1_hashes": list(set(SHA1_RE.findall(text))),
        "md5_hashes": list(set(MD5_RE.findall(text))),
    }


def detect_malware_families(text: str) -> list[str]:
    """Detect ransomware/malware family names in text."""
    lower = text.lower()
    return [f for f in RANSOMWARE_FAMILIES if f in lower]


def detect_c2_patterns(text: str) -> list[str]:
    """Detect C2 framework indicators in text."""
    lower = text.lower()
    return [c for c in C2_INDICATORS if c in lower]


def scan_repo(repo_path: Path, max_files: int = 5000) -> dict:
    """Scan a single repository and extract CTI-relevant data."""
    result = {
        "repo_name": repo_path.name,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "file_hashes": [],
        "extracted_iocs": {
            "cves": [], "attack_techniques": [], "ipv4": [],
            "domains": [], "urls": [], "emails": [],
            "sha256_hashes": [], "sha1_hashes": [], "md5_hashes": [],
        },
        "malware_families": [],
        "c2_indicators": [],
        "notable_files": [],
        "readme_summary": "",
        "file_count": 0,
        "total_size_bytes": 0,
    }

    all_cves = set()
    all_techniques = set()
    all_ipv4 = set()
    all_domains = set()
    all_urls = set()
    all_emails = set()
    all_sha256 = set()
    all_sha1 = set()
    all_md5 = set()
    all_families = set()
    all_c2 = set()

    files_scanned = 0

    for root, dirs, files in os.walk(repo_path):
        # Skip .git and other noise
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            fpath = Path(root) / fname

            try:
                stat = fpath.stat()
                result["total_size_bytes"] += stat.st_size
            except OSError:
                continue

            result["file_count"] += 1
            files_scanned += 1

            if files_scanned > max_files:
                break

            # Hash binary/executable files
            if should_hash(fpath):
                sha256 = compute_sha256(fpath)
                if sha256:
                    result["file_hashes"].append({
                        "file": str(fpath.relative_to(repo_path)),
                        "sha256": sha256,
                        "size_bytes": stat.st_size,
                    })

            # Extract text patterns from readable files
            try:
                if fpath.suffix.lower() in {'.py', '.ps1', '.sh', '.bat', '.cmd', '.vbs',
                                             '.js', '.yml', '.yaml', '.json', '.xml', '.conf',
                                             '.txt', '.md', '.csv', '.c', '.cpp', '.h', '.go',
                                             '.rs', '.rb', '.lua', '.toml', '.cfg', '.ini'}:
                    if stat.st_size < 1_000_000:  # Skip files >1MB for text extraction
                        text = fpath.read_text(encoding='utf-8', errors='ignore')
                        patterns = extract_patterns(text)
                        all_cves.update(patterns["cves"])
                        all_techniques.update(patterns["attack_techniques"])
                        all_ipv4.update(patterns["ipv4"])
                        all_domains.update(patterns["domains"])
                        all_urls.update(patterns["urls"])
                        all_emails.update(patterns["emails"])
                        all_sha256.update(patterns["sha256_hashes"])
                        all_sha1.update(patterns["sha1_hashes"])
                        all_md5.update(patterns["md5_hashes"])

                        families = detect_malware_families(text)
                        all_families.update(families)

                        c2 = detect_c2_patterns(text)
                        all_c2.update(c2)

                        # Track notable files with high signal
                        signal = (len(patterns["cves"]) + len(patterns["ipv4"]) +
                                  len(patterns["domains"]) + len(families) +
                                  len(patterns["attack_techniques"]))
                        if signal >= 2:
                            result["notable_files"].append({
                                "file": str(fpath.relative_to(repo_path)),
                                "cves": patterns["cves"],
                                "techniques": patterns["attack_techniques"],
                                "families": families,
                                "signal_score": signal,
                            })
            except (OSError, UnicodeDecodeError):
                pass

    # Read README
    for readme in ["README.md", "README.rst", "README.txt", "readme.md"]:
        readme_path = repo_path / readme
        if readme_path.exists():
            try:
                result["readme_summary"] = readme_path.read_text(encoding='utf-8', errors='ignore')[:2000]
            except OSError:
                pass
            break

    # Deduplicated results
    result["extracted_iocs"] = {
        "cves": sorted(all_cves),
        "attack_techniques": sorted(all_techniques),
        "ipv4": sorted(all_ipv4),
        "domains": sorted(all_domains),
        "urls": sorted(all_urls)[:100],  # Cap URLs
        "emails": sorted(all_emails),
        "sha256_hashes": sorted(all_sha256)[:50],
        "sha1_hashes": sorted(all_sha1)[:50],
        "md5_hashes": sorted(all_md5)[:50],
    }
    result["malware_families"] = sorted(all_families)
    result["c2_indicators"] = sorted(all_c2)

    return result


def main():
    repos_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "z-zoidberg" / "repos"
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.home() / "necti-data" / "repo-analysis"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for repo_dir in sorted(repos_dir.iterdir()):
        if not repo_dir.is_dir() or repo_dir.name.startswith('.'):
            continue

        print(f"Scanning: {repo_dir.name}...", end=" ", flush=True)
        result = scan_repo(repo_dir)
        all_results.append(result)

        # Save individual result
        out_path = output_dir / f"{repo_dir.name}.json"
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

        cves = len(result["extracted_iocs"]["cves"])
        hashes = len(result["file_hashes"])
        families = len(result["malware_families"])
        techniques = len(result["extracted_iocs"]["attack_techniques"])
        print(f"✓ {result['file_count']} files, {hashes} hashes, {cves} CVEs, {techniques} ATT&CK, {families} families")

    # Summary
    summary_path = output_dir / "summary.json"
    summary = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_repos": len(all_results),
        "total_files": sum(r["file_count"] for r in all_results),
        "total_hashes": sum(len(r["file_hashes"]) for r in all_results),
        "all_cves": sorted(set(cve for r in all_results for cve in r["extracted_iocs"]["cves"])),
        "all_techniques": sorted(set(t for r in all_results for t in r["extracted_iocs"]["attack_techniques"])),
        "all_families": sorted(set(f for r in all_results for f in r["malware_families"])),
        "all_c2_indicators": sorted(set(c for r in all_results for c in r["c2_indicators"])),
        "repos": [{"name": r["repo_name"], "files": r["file_count"], "hashes": len(r["file_hashes"]),
                    "cves": len(r["extracted_iocs"]["cves"]), "families": len(r["malware_families"])}
                   for r in all_results],
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n=== Summary ===")
    print(f"Repos: {summary['total_repos']}")
    print(f"Files: {summary['total_files']}")
    print(f"Hashes: {summary['total_hashes']}")
    print(f"Unique CVEs: {len(summary['all_cves'])}")
    print(f"ATT&CK techniques: {len(summary['all_techniques'])}")
    print(f"Malware families: {len(summary['all_families'])}")
    print(f"Output: {output_dir}")


if __name__ == "__main__":
    main()
