#!/usr/bin/env python3
"""Sigma-to-GitHub search bridge.

Extracts keywords from Sigma rules and searches GitHub for matching repos.
This lets us find offensive security repos that match our detection coverage.

Usage:
  python3 sigma_github_bridge.py [--rules-dir DIR] [--output DIR]
"""

import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote_plus
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def extract_sigma_keywords(rule_path: Path) -> dict:
    """Extract searchable keywords from a Sigma rule."""
    text = rule_path.read_text(encoding='utf-8', errors='ignore')

    # Extract title, description, detection keywords
    title = ""
    description = ""
    keywords = []

    for line in text.split('\n'):
        line = line.strip()
        if line.startswith('title:'):
            title = line.split(':', 1)[1].strip().strip('"')
        elif line.startswith('description:'):
            description = line.split(':', 1)[1].strip().strip('"')
        elif line.startswith('keywords:'):
            pass
        elif line.startswith('- ') and not line.startswith('- %'):
            # List items (service names, process names, etc.)
            val = line[2:].strip().strip('"').strip("'")
            if len(val) > 3 and not val.startswith('{'):
                keywords.append(val)

    # Extract key terms from title and description
    terms = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', f"{title} {description}")
    terms = [t for t in terms if len(t) > 4]

    # Extract CVE references
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)

    # Extract ATT&CK technique references
    techniques = re.findall(r'T\d{4}(?:\.\d{3})?', text)

    return {
        "rule_file": rule_path.name,
        "title": title,
        "description": description[:200],
        "keywords": keywords[:20],
        "terms": terms[:10],
        "cves": cves,
        "techniques": techniques,
    }


def github_search(query: str, token: str = "", limit: int = 5) -> list[dict]:
    """Search GitHub repos."""
    results = []
    url = f"https://api.github.com/search/repositories?q={quote_plus(query)}&sort=stars&per_page={limit}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        for r in data.get("items", []):
            results.append({
                "full_name": r["full_name"],
                "stars": r["stargazers_count"],
                "size_mb": round(r["size"] / 1024, 1),
                "description": (r.get("description") or "")[:100],
            })
    except (HTTPError, Exception):
        pass
    return results


def main():
    # Use the Sigma rules from the SK platform or a local checkout
    rules_dirs = [
        Path.home() / "z-zoidberg" / "security-knowledge" / "detections",
        Path.home() / "sigma" / "rules",
    ]

    rules_dir = None
    for d in rules_dirs:
        if d.exists():
            rules_dir = d
            break

    if not rules_dir:
        print("No Sigma rules directory found. Clone https://github.com/SigmaHQ/sigma first.")
        print("  git clone --depth 1 https://github.com/SigmaHQ/sigma.git ~/sigma")
        sys.exit(1)

    token = ""
    token_file = Path.home() / ".github_token"
    if token_file.exists():
        token = token_file.read_text().strip()

    output_dir = Path.home() / "necti-data" / "sigma-github-search"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Find all Sigma rules
    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    print(f"Found {len(rule_files)} Sigma rules in {rules_dir}")

    # Sample rules (don't search all - too many API calls)
    # Focus on rules with CVEs or specific technique references
    high_value_rules = []
    for rf in rule_files[:500]:
        try:
            info = extract_sigma_keywords(rf)
            if info["cves"] or len(info["techniques"]) > 0:
                high_value_rules.append(info)
        except Exception:
            pass

    print(f"High-value rules (with CVEs or ATT&CK): {len(high_value_rules)}")

    # Search GitHub for each
    search_results = {}
    searched = 0

    for rule in high_value_rules[:30]:  # Limit to 30 searches
        # Build search query from the most specific terms
        if rule["cves"]:
            query = f"{rule['cves'][0]} exploit poc"
        elif rule["techniques"]:
            query = f"MITRE {rule['techniques'][0]} red team"
        elif rule["terms"]:
            query = f"{' '.join(rule['terms'][:3])} exploit malware"
        else:
            continue

        print(f"  Searching: {query[:60]}...", end=" ", flush=True)
        repos = github_search(query, token=token, limit=5)
        search_results[rule["rule_file"]] = {
            "rule_title": rule["title"],
            "query": query,
            "repos": repos,
        }
        print(f"{len(repos)} repos")
        searched += 1
        time.sleep(7)  # Rate limit

    # Save results
    out_path = output_dir / "sigma_github_results.json"
    out_path.write_text(json.dumps(search_results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nSearched {searched} rules, found {sum(len(v['repos']) for v in search_results.values())} repos")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
