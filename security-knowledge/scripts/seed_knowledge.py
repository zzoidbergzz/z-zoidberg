"""Seed the knowledge database from the z.je/static/knowledge.md corpus.

Usage:
    python scripts/seed_knowledge.py

Requirements: pip install asyncpg

This script:
1. Seeds threat actors with aliases (stored in entities.aliases JSONB)
2. Seeds ransomware families with CISA advisory links
3. Seeds DLLs, system processes, and LOLBINs as tool entities
4. Seeds feed sources into source_records
5. Deduplicates by canonical_name + kind + tenant_id
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

DB_URL = os.environ.get("DATABASE_URL", "postgresql://sk:sk@localhost:5432/sk")
DB_URL = DB_URL.replace("postgresql+asyncpg://", "postgresql://")
TENANT_ID = os.environ.get("TENANT_ID", "00000000-0000-0000-0000-000000000000")

THREAT_ACTORS = [
    {"canonical_name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "Dark Halo", "Nobelium", "UNC2452", "YTTRIUM"],
     "description": "SVR-linked. Long-term intelligence collection, stealthy access. SolarWinds, DNC, COVID vaccine targeting."},
    {"canonical_name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Pawn Storm", "Iron Twilight"],
     "description": "GRU Unit 26165. Noisier than APT29. NotPetya, Olympic Destroyer, DNC intrusion."},
    {"canonical_name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Zinc", "APT38", "BlueNoroff", "Andariel"],
     "description": "DPRK-linked. Espionage + financially motivated. Bangladesh Bank, WannaCry, crypto exchange thefts."},
    {"canonical_name": "APT41", "aliases": ["Double Dragon", "Barium", "Wicked Panda", "Winnti"],
     "description": "Chinese cluster. Supply-chain targeting, mobile malware, gaming-sector intrusions."},
    {"canonical_name": "FIN7", "aliases": ["Carbanak", "Cobalt Group"],
     "description": "Financially motivated. Carbanak malware, retail/hospitality targeting."},
    {"canonical_name": "Sandworm", "aliases": ["IRIDIUM", "ELECTRUM", "Telebots", "Voodoo Bear", "Seashell Blizzard"],
     "description": "GRU Unit 74455. Destructive ops, Ukraine attacks, NotPetya, AcidPour."},
    {"canonical_name": "Turla", "aliases": ["Snake", "KRYPTON", "Venomous Bear"],
     "description": "FSB-linked. Satellite-based C2, long-lived espionage."},
    {"canonical_name": "Equation Group", "aliases": ["EQGRP"],
     "description": "Linked to NSA TAO. Advanced implants, firmware targeting, Shadow Brokers."},
    {"canonical_name": "Evil Corp", "aliases": ["Indrik Spider", "UNC2165"],
     "description": "Dridex, BitPaymer. Sanctions context, affiliate relationships."},
    {"canonical_name": "LockBit", "aliases": ["LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBitSupp"],
     "description": "Ransomware-as-a-service. Affiliate program, support-chat, leak-site lifecycle."},
    {"canonical_name": "BlackCat", "aliases": ["ALPHV", "ALPHV/BlackCat", "Noberus"],
     "description": "Rust-based ransomware. Triple extortion, seizure events, rebranding."},
    {"canonical_name": "Conti", "aliases": ["Ryuk", "TrickBot"],
     "description": "Leaked chats. TrickBot, Ryuk lineage, public-sector impacts."},
    {"canonical_name": "Cl0p", "aliases": ["TA505", "FIN11"],
     "description": "Mass exploitation of file transfer products. MOVEit, Accellion, GoAnywhere."},
    {"canonical_name": "Play", "aliases": ["PlayCrypt"],
     "description": "Volume-driven ransomware. ESXi, enterprise targeting."},
    {"canonical_name": "Akira", "aliases": ["Megazord"],
     "description": "Linux/VMware-targeting ransomware. VPN exploitation, double extortion."},
    {"canonical_name": "RansomHub", "aliases": ["Ransom Hub"],
     "description": "Ransomware-as-a-service. Active in 2024. CISA advisory AA24-242A."},
    {"canonical_name": "Medusa", "aliases": ["MedusaLocker"],
     "description": "Ransomware targeting healthcare, education. CISA advisory AA25-071A."},
    {"canonical_name": "Rhysida", "aliases": [],
     "description": "Ransomware targeting healthcare, education. CISA advisory AA23-319A."},
    {"canonical_name": "BianLian", "aliases": [],
     "description": "Go-based ransomware. Pivot to extortion-only. CISA advisory AA23-136A."},
    {"canonical_name": "Royal", "aliases": ["BlackSuit"],
     "description": "Ransomware targeting government, education. CISA advisory AA23-061A."},
]

RANSOMWARE_FAMILIES = [
    {"name": "RansomHub", "advisory": "CISA AA24-242A"},
    {"name": "Medusa", "advisory": "CISA AA25-071A"},
    {"name": "Rhysida", "advisory": "CISA AA23-319A"},
    {"name": "BianLian", "advisory": "CISA AA23-136A"},
    {"name": "Royal", "advisory": "CISA AA23-061A"},
    {"name": "Vice Society", "advisory": "CISA AA22-249A"},
    {"name": "MedusaLocker", "advisory": "CISA AA22-181A"},
]

CORE_DLLS = [
    "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "ws2_32.dll",
    "crypt32.dll", "cryptbase.dll", "vaultcli.dll", "samlib.dll", "dbghelp.dll",
    "version.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "mscoree.dll",
    "clrjit.dll", "mscorwks.dll", "ole32.dll", "shell32.dll", "shlwapi.dll",
    "powrprof.dll", "taskschd.dll", "rasapi32.dll", "dnsapi.dll", "iphlpapi.dll",
    "mpr.dll", "credui.dll", "sspicli.dll", "kerberos.dll", "lsasrv.dll",
]

SYSTEM_PROCESSES = ["svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe"]

LOLBINS = [
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "regsvr32.exe", "msiexec.exe", "installutil.exe", "cmd.exe", "powershell.exe",
    "wmiprvse.exe", "mmc.exe", "msbuild.exe", "csc.exe", "vssadmin.exe", "wbadmin.exe",
    "bcdedit.exe", "diskshadow.exe", "esentutl.exe", "extrac32.exe", "findstr.exe",
    "ftp.exe", "bitsadmin.exe", "expand.exe", "forfiles.exe", "hh.exe", "ieexec.exe",
    "iexpress.exe", "makecab.exe", "replace.exe", "rpcping.exe", "presentationhost.exe",
    "ilasm.exe", "infdefaultinstall.exe",
]

FEED_SOURCES = [
    {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "title": "NVD CVE Feed", "kind": "api", "source_type": "nvd"},
    {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "title": "CISA KEV Feed", "kind": "feed", "source_type": "json"},
    {"url": "https://api.github.com/advisories", "title": "GitHub Security Advisories", "kind": "api", "source_type": "github"},
]


async def seed() -> dict:
    import asyncpg

    conn = await asyncpg.connect(DB_URL)
    tid = uuid.UUID(TENANT_ID)
    stats = {"actors": 0, "families": 0, "dlls": 0, "lolbins": 0, "feeds": 0}

    # ── Threat Actors ──
    for actor in THREAT_ACTORS:
        existing = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND kind = 'actor' AND tenant_id = $2",
            actor["canonical_name"], tid,
        )
        if existing:
            # Update aliases on existing entity
            current_refs = await conn.fetchval(
                "SELECT external_refs FROM entities WHERE id = $1", existing,
            )
            refs = json.loads(current_refs) if current_refs else {}
            refs["description"] = actor["description"]
            # Merge aliases
            current_aliases = await conn.fetchval(
                "SELECT aliases FROM entities WHERE id = $1", existing,
            )
            existing_aliases = json.loads(current_aliases) if current_aliases else []
            merged_aliases = list(set(existing_aliases + actor["aliases"]))
            await conn.execute(
                "UPDATE entities SET aliases = $1, external_refs = $2, updated_at = now() WHERE id = $3",
                json.dumps(merged_aliases), json.dumps(refs), existing,
            )
            logger.info(f"Updated actor: {actor['canonical_name']} ({len(merged_aliases)} aliases)")
        else:
            entity_id = uuid.uuid4()
            refs = {"description": actor["description"]}
            await conn.execute(
                """INSERT INTO entities (id, tenant_id, kind, canonical_name, aliases, external_refs)
                   VALUES ($1, $2, 'actor', $3, $4, $5)""",
                entity_id, tid, actor["canonical_name"],
                json.dumps(actor["aliases"]), json.dumps(refs),
            )
            stats["actors"] += 1
            logger.info(f"Created actor: {actor['canonical_name']} ({len(actor['aliases'])} aliases)")

    # ── Ransomware Families ──
    for fam in RANSOMWARE_FAMILIES:
        existing = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND kind = 'malware' AND tenant_id = $2",
            fam["name"], tid,
        )
        if not existing:
            await conn.execute(
                """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                   VALUES ($1, $2, 'malware', $3, $4)""",
                uuid.uuid4(), tid, fam["name"],
                json.dumps({"advisory": fam["advisory"]}),
            )
            stats["families"] += 1
            logger.info(f"Created malware: {fam['name']}")

    # ── DLLs ──
    for dll in CORE_DLLS + SYSTEM_PROCESSES:
        existing = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND kind = 'tool' AND tenant_id = $2",
            dll, tid,
        )
        if not existing:
            await conn.execute(
                """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                   VALUES ($1, $2, 'tool', $3, $4)""",
                uuid.uuid4(), tid, dll, '{"category": "dll"}',
            )
            stats["dlls"] += 1

    # ── LOLBINs ──
    for lolbin in LOLBINS:
        existing = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND kind = 'tool' AND tenant_id = $2",
            lolbin, tid,
        )
        if not existing:
            await conn.execute(
                """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                   VALUES ($1, $2, 'tool', $3, $4)""",
                uuid.uuid4(), tid, lolbin, '{"category": "lolbin"}',
            )
            stats["lolbins"] += 1

    # ── Feed Sources ──
    for src in FEED_SOURCES:
        existing = await conn.fetchval(
            "SELECT id FROM source_records WHERE url = $1 AND tenant_id = $2",
            src["url"], tid,
        )
        if not existing:
            await conn.execute(
                """INSERT INTO source_records (id, tenant_id, url, title, kind, source_type, active, fetch_interval_seconds)
                   VALUES ($1, $2, $3, $4, $5, $6, true, 1200)""",
                uuid.uuid4(), tid, src["url"], src["title"], src["kind"], src["source_type"],
            )
            stats["feeds"] += 1
            logger.info(f"Created feed source: {src['title']}")

    await conn.close()
    return stats


if __name__ == "__main__":
    result = asyncio.run(seed())
    print(f"Seeded: {result}")
