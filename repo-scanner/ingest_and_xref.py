#!/usr/bin/env python3
"""Ingest repo scan data into z.je SK platform with cross-referencing.

Reads scan results from ~/necti-data/repo-analysis/*.json
Cross-references against existing entities for matches.
Creates new entities for novel findings.
Produces detailed report.
"""

import asyncio
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path.home() / "z-zoidberg" / "security-knowledge"))

from app.database import AsyncSessionLocal
from app.models.entities import Entity
from sqlalchemy import select, func, text

TENANT_ID = "bcc8ab78-0982-4ea3-81d3-7e4bd166881a"

# --- Cross-reference results ---
class CrossRefResults:
    def __init__(self):
        self.cve_matches = []       # (cve_id, existing_entity_name, repo_source)
        self.cve_new = []           # (cve_id, repo_source)
        self.hash_matches = []      # (sha256, existing_entity_name, repo_source, repo_file)
        self.hash_new = []          # (sha256, repo_source, repo_file)
        self.family_matches = []    # (family, existing_entity_name, repo_source)
        self.family_new = []        # (family, repo_source)
        self.technique_matches = [] # (technique_id, existing_entity_name, repo_source)
        self.technique_new = []     # (technique_id, repo_source)
        self.actor_matches = []     # actor names found in both scan + existing entities
        self.repos_processed = 0
        self.entities_created = 0


async def load_existing_lookups(db) -> dict:
    """Build lookup dicts from existing entities for fast cross-ref."""
    lookups = {
        "cve_by_name": {},       # lowercase name -> entity
        "hash_by_name": {},      # sha256 -> entity
        "hash_by_ref": {},       # sha256 from external_refs -> entity
        "malware_by_name": {},   # lowercase name -> entity
        "attack_by_id": {},      # technique ID -> entity
        "actor_by_name": {},     # lowercase name -> entity
    }

    # CVEs
    result = await db.execute(
        select(Entity.canonical_name, Entity.external_refs)
        .where(Entity.kind == "cve")
    )
    for name, refs in result.all():
        if name:
            lookups["cve_by_name"][name.lower()] = name
            # Also index by external_refs CVE IDs
            if refs and "cve_id" in refs:
                lookups["cve_by_name"][refs["cve_id"].lower()] = name

    # Hashes
    result = await db.execute(
        select(Entity.canonical_name, Entity.external_refs)
        .where(Entity.kind == "hash")
    )
    for name, refs in result.all():
        if name:
            lookups["hash_by_name"][name.lower()] = name
        if refs:
            for key in ("sha256", "hash"):
                if key in refs:
                    lookups["hash_by_ref"][refs[key].lower()] = name

    # Malware
    result = await db.execute(
        select(Entity.canonical_name)
        .where(Entity.kind == "malware")
    )
    for (name,) in result.all():
        if name:
            lookups["malware_by_name"][name.lower()] = name

    # Attack patterns
    result = await db.execute(
        select(Entity.canonical_name, Entity.external_refs)
        .where(Entity.kind.in_(["attack_pattern", "technique", "subtechnique"]))
    )
    for name, refs in result.all():
        if name:
            lookups["attack_by_id"][name.upper()] = name
        if refs and "mitre_attack_id" in refs:
            lookups["attack_by_id"][refs["mitre_attack_id"].upper()] = name

    # Threat actors
    result = await db.execute(
        select(Entity.canonical_name)
        .where(Entity.kind.in_(["threat_actor", "actor"]))
    )
    for (name,) in result.all():
        if name:
            lookups["actor_by_name"][name.lower()] = name

    return lookups


async def ingest_scan_results(lookups: dict, results: CrossRefResults):
    """Process scan results, cross-reference, and create entities."""
    scan_dir = Path.home() / "necti-data" / "repo-analysis"

    for scan_file in sorted(scan_dir.glob("*.json")):
        if scan_file.name == "summary.json":
            continue

        try:
            scan = json.loads(scan_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        repo_name = scan.get("repo_name", scan_file.stem)
        results.repos_processed += 1
        source_ref = f"repo-scan:{repo_name}"

        # --- Cross-reference CVEs ---
        for cve_id in scan.get("extracted_iocs", {}).get("cves", []):
            cve_upper = cve_id.upper()
            if cve_upper in lookups["cve_by_name"] or cve_upper.lower() in lookups["cve_by_name"]:
                existing = lookups["cve_by_name"].get(cve_upper, lookups["cve_by_name"].get(cve_upper.lower(), cve_upper))
                results.cve_matches.append((cve_upper, existing, repo_name))
            else:
                results.cve_new.append((cve_upper, repo_name))
                lookups["cve_by_name"][cve_upper.lower()] = cve_upper

        # --- Cross-reference hashes ---
        for fh in scan.get("file_hashes", []):
            sha256 = fh.get("sha256", "")
            fpath = fh.get("file", "")
            if sha256.lower() in lookups["hash_by_ref"]:
                existing = lookups["hash_by_ref"][sha256.lower()]
                results.hash_matches.append((sha256[:16] + "...", existing, repo_name, fpath))
            elif sha256.lower() in lookups["hash_by_name"]:
                existing = lookups["hash_by_name"][sha256.lower()]
                results.hash_matches.append((sha256[:16] + "...", existing, repo_name, fpath))
            else:
                results.hash_new.append((sha256, repo_name, fpath))
                lookups["hash_by_ref"][sha256.lower()] = sha256

        # --- Cross-reference malware families ---
        for family in scan.get("malware_families", []):
            if family.lower() in lookups["malware_by_name"]:
                existing = lookups["malware_by_name"][family.lower()]
                results.family_matches.append((family, existing, repo_name))
            else:
                results.family_new.append((family, repo_name))
                lookups["malware_by_name"][family.lower()] = family

        # --- Cross-reference ATT&CK techniques ---
        for tech_id in scan.get("extracted_iocs", {}).get("attack_techniques", []):
            tech_upper = tech_id.upper()
            if tech_upper in lookups["attack_by_id"]:
                existing = lookups["attack_by_id"][tech_upper]
                results.technique_matches.append((tech_upper, existing, repo_name))
            else:
                results.technique_new.append((tech_upper, repo_name))
                lookups["attack_by_id"][tech_upper] = tech_upper

    return results


async def create_new_entities(db, lookups: dict, results: CrossRefResults):
    """Create new entities in the SK platform for novel findings."""
    created = 0
    batch = []

    # Create new CVE entities (deduped)
    seen_cves = set()
    for cve_id, repo_name in results.cve_new:
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        batch.append(Entity(
            tenant_id=TENANT_ID,
            kind="cve",
            canonical_name=cve_id,
            external_refs={
                "source": "repo-scanner",
                "repo": repo_name,
                "cve_id": cve_id,
            },
        ))

    # Create new hash entities (deduped, max 500 to avoid overload)
    seen_hashes = set()
    for sha256, repo_name, fpath in results.hash_new[:500]:
        if sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)
        batch.append(Entity(
            tenant_id=TENANT_ID,
            kind="hash",
            canonical_name=sha256[:64],
            external_refs={
                "source": "repo-scanner",
                "sha256": sha256,
                "repo": repo_name,
                "file": fpath,
            },
        ))

    # Create new malware family entities
    seen_families = set()
    for family, repo_name in results.family_new:
        if family in seen_families:
            continue
        seen_families.add(family)
        batch.append(Entity(
            tenant_id=TENANT_ID,
            kind="malware",
            canonical_name=family.title(),
            external_refs={
                "source": "repo-scanner",
                "family": family,
                "repo": repo_name,
            },
        ))

    # Create new technique entities
    seen_tech = set()
    for tech_id, repo_name in results.technique_new:
        if tech_id in seen_tech:
            continue
        seen_tech.add(tech_id)
        batch.append(Entity(
            tenant_id=TENANT_ID,
            kind="attack_pattern",
            canonical_name=f"MITRE ATT&CK {tech_id}",
            external_refs={
                "source": "repo-scanner",
                "mitre_attack_id": tech_id,
                "repo": repo_name,
            },
        ))

    # Batch insert
    if batch:
        db.add_all(batch)
        await db.commit()
        created = len(batch)

    results.entities_created = created
    return results


def generate_report(results: CrossRefResults, lookups: dict, scan_dir: Path) -> str:
    """Generate detailed cross-reference report."""
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("=" * 80)
    lines.append("OFFENSIVE SECURITY REPO SCAN — INGESTION & CROSS-REFERENCE REPORT")
    lines.append(f"Generated: {now}")
    lines.append("=" * 80)
    lines.append("")

    # Summary
    lines.append("1. EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"   Repos scanned:              {results.repos_processed}")
    lines.append(f"   New entities created:       {results.entities_created}")
    lines.append(f"   CVE matches (existing DB):  {len(results.cve_matches)}")
    lines.append(f"   CVE new (added):            {len(set(c[0] for c in results.cve_new))}")
    lines.append(f"   Hash matches (existing DB): {len(results.hash_matches)}")
    lines.append(f"   Hash new (added):           {len(set(h[0] for h in results.hash_new))}")
    lines.append(f"   Malware family matches:     {len(results.family_matches)}")
    lines.append(f"   Malware family new:         {len(set(f[0] for f in results.family_new))}")
    lines.append(f"   ATT&CK technique matches:   {len(results.technique_matches)}")
    lines.append(f"   ATT&CK technique new:       {len(set(t[0] for t in results.technique_new))}")
    lines.append("")

    # Database stats
    total_existing = sum(len(v) for v in lookups.values())
    lines.append("2. DATABASE CROSS-REFERENCE BASELINE")
    lines.append("-" * 40)
    lines.append(f"   Existing CVEs indexed:      {len(lookups['cve_by_name'])}")
    lines.append(f"   Existing hashes indexed:    {len(lookups['hash_by_name']) + len(lookups['hash_by_ref'])}")
    lines.append(f"   Existing malware indexed:   {len(lookups['malware_by_name'])}")
    lines.append(f"   Existing ATT&CK indexed:    {len(lookups['attack_by_id'])}")
    lines.append(f"   Existing actors indexed:    {len(lookups['actor_by_name'])}")
    lines.append("")

    # CVE matches detail
    lines.append("3. CVE CROSS-REFERENCE MATCHES")
    lines.append("-" * 40)
    cve_match_by_repo = defaultdict(list)
    for cve_id, existing, repo in results.cve_matches:
        cve_match_by_repo[repo].append((cve_id, existing))
    for repo in sorted(cve_match_by_repo.keys()):
        entries = cve_match_by_repo[repo]
        lines.append(f"   {repo} ({len(entries)} matches):")
        for cve_id, existing in sorted(entries)[:20]:
            lines.append(f"     {cve_id:20s} → DB: {existing}")
        if len(entries) > 20:
            lines.append(f"     ... and {len(entries)-20} more")
    lines.append("")

    # CVE new
    lines.append("4. NEW CVEs (NOT IN DATABASE)")
    lines.append("-" * 40)
    new_cve_set = sorted(set(c[0] for c in results.cve_new))
    lines.append(f"   Total new CVEs: {len(new_cve_set)}")
    for cve in new_cve_set[:50]:
        repos = [r for c, r in results.cve_new if c == cve]
        lines.append(f"     {cve:20s} ← {', '.join(set(repos))}")
    if len(new_cve_set) > 50:
        lines.append(f"   ... and {len(new_cve_set)-50} more")
    lines.append("")

    # Hash matches
    lines.append("5. HASH CROSS-REFERENCE MATCHES")
    lines.append("-" * 40)
    lines.append(f"   Hashes matching existing DB: {len(results.hash_matches)}")
    for sha_short, existing, repo, fpath in results.hash_matches[:30]:
        lines.append(f"     {sha_short} → DB: {existing} ← {repo}/{fpath}")
    if len(results.hash_matches) > 30:
        lines.append(f"   ... and {len(results.hash_matches)-30} more")
    lines.append("")

    # Hash new
    lines.append("6. NEW FILE HASHES (ADDED TO DATABASE)")
    lines.append("-" * 40)
    new_hash_set = set(h[0] for h in results.hash_new)
    lines.append(f"   Total new SHA256 hashes: {len(new_hash_set)}")
    # Group by repo
    hash_by_repo = defaultdict(list)
    for sha256, repo, fpath in results.hash_new:
        hash_by_repo[repo].append((sha256, fpath))
    for repo in sorted(hash_by_repo.keys()):
        entries = hash_by_repo[repo]
        lines.append(f"   {repo}: {len(entries)} hashes")
        for sha256, fpath in sorted(entries, key=lambda x: x[1])[:10]:
            lines.append(f"     {sha256[:32]}...  {fpath}")
        if len(entries) > 10:
            lines.append(f"     ... and {len(entries)-10} more")
    lines.append("")

    # Malware families
    lines.append("7. MALWARE FAMILY CROSS-REFERENCE")
    lines.append("-" * 40)
    lines.append(f"   Families matching existing DB: {len(results.family_matches)}")
    for family, existing, repo in sorted(results.family_matches):
        lines.append(f"     {family:20s} → DB: {existing} ← {repo}")
    lines.append("")
    lines.append(f"   New families (added): {len(set(f[0] for f in results.family_new))}")
    for family, repo in sorted(set(results.family_new)):
        lines.append(f"     {family:20s} ← {repo}")
    lines.append("")

    # ATT&CK techniques
    lines.append("8. MITRE ATT&CK TECHNIQUE CROSS-REFERENCE")
    lines.append("-" * 40)
    lines.append(f"   Techniques matching existing DB: {len(results.technique_matches)}")
    # Dedupe
    tech_match_deduped = {}
    for tech_id, existing, repo in results.technique_matches:
        if tech_id not in tech_match_deduped:
            tech_match_deduped[tech_id] = (existing, [repo])
        else:
            tech_match_deduped[tech_id][1].append(repo)
    for tech_id in sorted(tech_match_deduped.keys())[:30]:
        existing, repos = tech_match_deduped[tech_id]
        lines.append(f"     {tech_id:12s} → DB: {existing} ← {', '.join(set(repos))}")
    if len(tech_match_deduped) > 30:
        lines.append(f"   ... and {len(tech_match_deduped)-30} more")
    lines.append("")
    lines.append(f"   New techniques (added): {len(set(t[0] for t in results.technique_new))}")
    for tech_id, repo in sorted(set(results.technique_new))[:20]:
        lines.append(f"     {tech_id:12s} ← {repo}")
    lines.append("")

    # Per-repo summary
    lines.append("9. PER-REPOSITORY SUMMARY")
    lines.append("-" * 40)
    scan_dir = Path.home() / "necti-data" / "repo-analysis"
    for scan_file in sorted(scan_dir.glob("*.json")):
        if scan_file.name == "summary.json":
            continue
        try:
            d = json.loads(scan_file.read_text(encoding='utf-8'))
            fc = d["file_count"]
            hc = len(d["file_hashes"])
            cves = len(d["extracted_iocs"]["cves"])
            techs = len(d["extracted_iocs"]["attack_techniques"])
            families = len(d["malware_families"])
            c2 = len(d["c2_indicators"])
            iocs = len(d["extracted_iocs"].get("ipv4", [])) + len(d["extracted_iocs"].get("domains", []))
            lines.append(f"   {d['repo_name']:40s}  {fc:5d} files  {hc:4d} hashes  {cves:3d} CVEs  {techs:3d} ATT&CK  {families:2d} families  {c2:2d} C2  {iocs:3d} IOCs")
        except:
            pass
    lines.append("")

    # Notable files (high signal)
    lines.append("10. NOTABLE HIGH-SIGNAL FILES")
    lines.append("-" * 40)
    all_notable = []
    for scan_file in sorted(scan_dir.glob("*.json")):
        if scan_file.name == "summary.json":
            continue
        try:
            d = json.loads(scan_file.read_text(encoding='utf-8'))
            for nf in d.get("notable_files", []):
                if nf["signal_score"] >= 3:
                    all_notable.append((d["repo_name"], nf))
        except:
            pass
    all_notable.sort(key=lambda x: x[1]["signal_score"], reverse=True)
    for repo, nf in all_notable[:40]:
        lines.append(f"   [{nf['signal_score']}] {repo}/{nf['file']}")
        if nf.get("cves"):
            lines.append(f"        CVEs: {', '.join(nf['cves'])}")
        if nf.get("techniques"):
            lines.append(f"        ATT&CK: {', '.join(nf['techniques'])}")
        if nf.get("families"):
            lines.append(f"        Families: {', '.join(nf['families'])}")
    lines.append("")

    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)


async def main():
    print("Loading existing entity lookups...", flush=True)
    async with AsyncSessionLocal() as db:
        lookups = await load_existing_lookups(db)
        print(f"  CVEs: {len(lookups['cve_by_name'])}, Hashes: {len(lookups['hash_by_ref'])}, "
              f"Malware: {len(lookups['malware_by_name'])}, ATT&CK: {len(lookups['attack_by_id'])}, "
              f"Actors: {len(lookups['actor_by_name'])}", flush=True)

    print("\nCross-referencing scan results...", flush=True)
    results = CrossRefResults()
    await ingest_scan_results(lookups, results)
    print(f"  CVE matches: {len(results.cve_matches)}, new: {len(set(c[0] for c in results.cve_new))}")
    print(f"  Hash matches: {len(results.hash_matches)}, new: {len(set(h[0] for h in results.hash_new))}")
    print(f"  Family matches: {len(results.family_matches)}, new: {len(set(f[0] for f in results.family_new))}")
    print(f"  ATT&CK matches: {len(results.technique_matches)}, new: {len(set(t[0] for t in results.technique_new))}")

    print("\nCreating new entities in database...", flush=True)
    async with AsyncSessionLocal() as db:
        await create_new_entities(db, lookups, results)
    print(f"  Created: {results.entities_created} entities")

    print("\nGenerating report...", flush=True)
    scan_dir = Path.home() / "necti-data" / "repo-analysis"
    report = generate_report(results, lookups, scan_dir)

    report_path = Path.home() / "necti-data" / "ingestion_report.txt"
    report_path.write_text(report, encoding="utf-8")
    print(f"  Report: {report_path}")
    print(f"  Size: {len(report):,} chars")


if __name__ == "__main__":
    asyncio.run(main())
