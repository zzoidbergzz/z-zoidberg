#!/usr/bin/env python3
"""Scan ~/repo/ directory."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / "z-zoidberg" / "repo-scanner"))
from scan_repos import scan_repo

output_dir = Path.home() / "necti-data" / "repo-analysis"
repo_dir = Path.home() / "repo"

for d in sorted(repo_dir.iterdir()):
    if not d.is_dir() or d.name.startswith("."):
        continue
    outfile = output_dir / f"{d.name}.json"
    if outfile.exists():
        print(f"  {d.name}: already scanned")
        continue
    print(f"  Scanning {d.name}...", end=" ", flush=True)
    result = scan_repo(d, max_files=3000)
    outfile.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    fc = result["file_count"]
    hc = len(result["file_hashes"])
    print(f"OK {fc} files, {hc} hashes")
