"""Seed the knowledge database from the z.je/static/knowledge.md corpus.

Usage:
    python scripts/seed_knowledge.py

Requirements: pip install asyncpg

This script:
1. Fetches knowledge.md from z.je
2. Extracts threat actor, DLL, LOLBIN, and incident entities
3. Creates entities with claims and relationships
4. Deduplicates by canonical_name + kind
5. Adds source URLs as SourceRecords for feed tracking
"""
from __future__ import annotations

import asyncio
import os
import uuid
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

KNOWLEDGE_URL = "https://z.je/static/knowledge.md"
DB_URL = os.environ.get("DATABASE_URL", "postgresql://sk:sk@localhost:5432/sk")
# Convert asyncpg URL to standard postgres URL if needed
DB_URL = DB_URL.replace("postgresql+asyncpg://", "postgresql://")
TENANT_ID = os.environ.get("TENANT_ID", "00000000-0000-0000-0000-000000000000")

# ── Threat Actors from knowledge.md ──────────────────────────────────────────

THREAT_ACTORS = [
    {"canonical_name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "Dark Halo", "Nobelium", "UNC2452"],
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
    {"canonical_name": "LockBit", "aliases": ["LockBit 2.0", "LockBit 3.0", "LockBit Black"],
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
    stats = {"actors": 0, "aliases": 0, "families": 0, "dlls": 0, "lolbins": 0, "feeds": 0}

    # ── Threat Actors ──
    for actor in THREAT_ACTORS:
        existing = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND kind = 'actor' AND tenant_id = $2",
            actor["canonical_name"], tid,
        )
        if existing:
            entity_id = existing
        else:
            entity_id = uuid.uuid4()
            await conn.execute(
                """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                   VALUES ($1, $2, 'actor', $3, $4)""",
                entity_id, tid, actor["canonical_name"],
                __import__("json").dumps({"description": actor["description"]}),
            )
            stats["actors"] += 1

        for alias in actor["aliases"]:
            existing_alias = await conn.fetchval(
                "SELECT id FROM entity_aliases WHERE entity_id = $1 AND alias = $2",
                entity_id, alias,
            )
            if not existing_alias:
                await conn.execute(
                    "INSERT INTO entity_aliases (id, entity_id, alias) VALUES ($1, $2, $3)",
                    uuid.uuid4(), entity_id, alias,
                )
                stats["aliases"] += 1

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
                __import__("json").dumps({"advisory": fam["advisory"]}),
            )
            stats["families"] += 1

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

    await conn.close()
    return stats


if __name__ == "__main__":
    result = asyncio.run(seed())
    print(f"Seeded: {result}")
