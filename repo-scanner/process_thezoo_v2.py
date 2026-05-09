#!/usr/bin/env python3
"""Re-process theZoo with correct family detection."""
import json, os, zipfile
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

repo = Path.home() / "z-zoidberg/repos/theZoo"
output = Path.home() / "necti-data/malware-processing/theZoo.json"

result = {
    "repo_name": "theZoo",
    "processed_at": datetime.now(timezone.utc).isoformat(),
    "zip_files_found": 0,
    "malware_entries": [],
    "family_counts": defaultdict(int),
    "total_binaries": 0,
    "errors": 0,
}

seen = set()
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != ".git"]
    for fname in files:
        fpath = Path(root) / fname
        if not fname.lower().endswith(".zip"):
            continue
        result["zip_files_found"] += 1

        # Family from path: theZoo/malware/Binaries/familyname/... or Source/Original/familyname/...
        try:
            rel = fpath.relative_to(repo)
            parts = rel.parts
            if len(parts) >= 5 and parts[0] == "malware" and parts[1] in ("Binaries", "Source"):
                family = parts[3]  # malware/Binaries/FAMILY/file.zip
            elif len(parts) >= 4 and parts[0] == "malware":
                family = parts[2]  # malware/FAMILY/file.zip
            else:
                family = parts[-2] if len(parts) >= 2 else "unknown"
            # Clean up family name
            family = family.replace(".", " ").replace("_", " ").strip()
        except Exception:
            family = "unknown"

        try:
            with zipfile.ZipFile(str(fpath)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size == 0:
                        continue
                    pseudo = f"{info.CRC:08x}:{info.filename}"
                    if pseudo in seen:
                        continue
                    seen.add(pseudo)
                    result["malware_entries"].append({
                        "crc32": f"{info.CRC:08x}",
                        "filename": info.filename,
                        "family": family,
                        "size": info.file_size,
                        "source": str(fpath.relative_to(repo)),
                    })
                    result["total_binaries"] += 1
                    result["family_counts"][family] += 1
        except Exception:
            result["errors"] += 1

result["family_counts"] = dict(sorted(result["family_counts"].items(), key=lambda x: x[1], reverse=True))
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"Done: {result['total_binaries']} binaries, {result['zip_files_found']} ZIPs, {len(result['family_counts'])} families, {result['errors']} errors")
