#!/usr/bin/env python3
"""GitHub search tool — find repos by CVE, MITRE ATT&CK, sigma keywords.

Uses GitHub Search API to discover offensive security repos matching
CTI-relevant criteria. Outputs a clone-ready list.

Rate limit: 10 requests/min unauthenticated, 30/min with token.
"""

import json
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.parse import quote_plus
from urllib.error import HTTPError


def github_search(query: str, sort: str = "stars", limit: int = 20, token: str = "") -> list[dict]:
    """Search GitHub repos. Returns list of {full_name, stars, size_mb, description, url}."""
    results = []
    per_page = min(limit, 100)
    page = 1

    while len(results) < limit:
        url = f"https://api.github.com/search/repositories?q={quote_plus(query)}&sort={sort}&per_page={per_page}&page={page}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 403:
                print(f"  Rate limited. Wait 60s...", file=sys.stderr)
                time.sleep(60)
                continue
            print(f"  HTTP {e.code}: {e.reason}", file=sys.stderr)
            break

        items = data.get("items", [])
        if not items:
            break

        for r in items:
            results.append({
                "full_name": r["full_name"],
                "stars": r["stargazers_count"],
                "size_mb": round(r["size"] / 1024, 1),
                "description": (r.get("description") or "")[:100],
                "url": r["html_url"],
                "language": r.get("language", ""),
                "topics": r.get("topics", []),
            })

        if len(items) < per_page:
            break
        page += 1
        time.sleep(6)  # Rate limit

    return results[:limit]


def search_by_cve(cve_id: str, token: str = "") -> list[dict]:
    """Find repos related to a specific CVE."""
    return github_search(f"{cve_id} exploit poc", sort="stars", limit=10, token=token)


def search_by_attack_technique(technique_id: str, token: str = "") -> list[dict]:
    """Find repos related to a MITRE ATT&CK technique."""
    return github_search(f"MITRE ATT&CK {technique_id}", sort="stars", limit=10, token=token)


def search_by_sigma_keyword(keyword: str, token: str = "") -> list[dict]:
    """Find repos matching sigma rule keywords."""
    return github_search(f"{keyword} detection sigma yara", sort="stars", limit=10, token=token)


def search_by_category(category: str, token: str = "") -> list[dict]:
    """Search by offensive security category."""
    queries = {
        "c2": "topic:c2-framework stars:>200",
        "ransomware": "topic:ransomware stars:>50",
        "malware-samples": "malware samples analysis stars:>100",
        "kernel-exploit": "kernel exploit privilege escalation stars:>100",
        "exploit-kit": "exploit kit framework stars:>100",
        "windows-lpe": "windows privilege escalation exploit stars:>100",
        "av-evasion": "antivirus evasion bypass stars:>200",
        "lateral-movement": "lateral movement pentest stars:>100",
        "persistence": "windows persistence implant stars:>100",
        "rootkit": "rootkit kernel stars:>200",
    }
    query = queries.get(category, f"{category} security stars:>100")
    return github_search(query, sort="stars", limit=20, token=token)


def main():
    token = ""
    token_file = Path.home() / ".github_token"
    if token_file.exists():
        token = token_file.read_text().strip()

    output_dir = Path.home() / "necti-data" / "github-search"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Search by categories
    all_results = {}
    categories = ["c2", "ransomware", "malware-samples", "kernel-exploit",
                  "windows-lpe", "av-evasion", "rootkit", "persistence"]

    for cat in categories:
        print(f"Searching: {cat}...", end=" ", flush=True)
        results = search_by_category(cat, token=token)
        all_results[cat] = results
        print(f"{len(results)} repos found")
        time.sleep(2)

    # Search by notable CVEs from 2024-2025
    notable_cves = [
        "CVE-2024-3094",   # XZ Utils backdoor
        "CVE-2024-1086",   # Linux netfilter LPE
        "CVE-2024-21762",  # FortiGate
        "CVE-2024-3400",   # Palo Alto
        "CVE-2023-44228",  # Log4Shell successor
        "CVE-2024-29847",  # Ivanti
        "CVE-2024-0001",   # Generic 2024
        "CVE-2025-0282",   # Ivanti 2025
    ]

    print("\nSearching by CVE...")
    all_cve_results = {}
    for cve in notable_cves:
        print(f"  {cve}...", end=" ", flush=True)
        results = search_by_cve(cve, token=token)
        all_cve_results[cve] = results
        print(f"{len(results)} repos")
        time.sleep(2)

    # Save results
    output = {
        "searched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "category_results": all_results,
        "cve_results": all_cve_results,
    }

    out_path = output_dir / "github_search_results.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")

    # Print summary with clone suggestions
    print(f"\n=== Top Repos to Clone (sorted by stars, <500MB) ===")
    all_repos = []
    seen = set()
    for cat, repos in all_results.items():
        for r in repos:
            if r["full_name"] not in seen and r["size_mb"] < 500:
                seen.add(r["full_name"])
                all_repos.append({**r, "category": cat})
    all_repos.sort(key=lambda x: x["stars"], reverse=True)

    for r in all_repos[:30]:
        print(f"  ★{r['stars']:5d}  {r['size_mb']:6.1f}MB  [{r['category']}]  {r['full_name']}")
        print(f"         {r['description']}")

    print(f"\nTotal unique repos: {len(all_repos)}")
    print(f"Output: {out_path}")

    # Generate clone script
    clone_script = output_dir / "clone_suggested.sh"
    with open(clone_script, 'w') as f:
        f.write("#!/bin/bash\n# Suggested repos to clone (from github search)\n")
        f.write("cd ~/z-zoidberg/repos\n\n")
        for r in all_repos:
            if r["size_mb"] < 300:  # Skip huge repos
                safe_name = r["full_name"].replace("/", "-")
                f.write(f"# ★{r['stars']} [{r['category']}] {r['description']}\n")
                f.write(f"git clone --depth 1 https://github.com/{r['full_name']}.git {safe_name}\n\n")
    clone_script.chmod(0o755)
    print(f"Clone script: {clone_script}")


if __name__ == "__main__":
    main()
