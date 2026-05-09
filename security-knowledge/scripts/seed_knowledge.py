"""Seed the knowledge database from the z.je/static/knowledge.md corpus.

Usage:
    python -m scripts.seed_knowledge

This script:
1. Fetches knowledge.md from z.je
2. Extracts threat actor, DLL, LOLBIN, and incident entities
3. Creates entities with claims and relationships
4. Deduplicates by canonical_name + kind
5. Adds source URLs as SourceRecords for feed tracking
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime

import httpx
import structlog

logger = structlog.get_logger(__name__)

KNOWLEDGE_URL = "https://z.je/static/knowledge.md"

# ── Threat Actors from knowledge.md ──────────────────────────────────────────

THREAT_ACTORS = [
    {
        "canonical_name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "Minidionis", "Dark Halo", "Nobelium", "UNC2452", "YTTRIUM"],
        "kind": "actor",
        "description": "SVR-linked operations. Known for long-term intelligence collection and stealthy access maintenance. Frequently linked to SolarWinds, DNC-related activity, and COVID vaccine targeting.",
        "sources": ["CISA AA22-110A"],
    },
    {
        "canonical_name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Tsar Team", "Iron Twilight", "Pawn Storm"],
        "kind": "actor",
        "description": "GRU Unit 26165. Known for noisier operations than APT29, but still heavily resourced. Frequently tied to NotPetya, Olympic Destroyer, and DNC intrusion activity.",
        "sources": ["CISA AA22-110A"],
    },
    {
        "canonical_name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Labyrinth Chollima", "APT38", "BlueNoroff", "Andariel", "Stardust Chollima"],
        "kind": "actor",
        "description": "DPRK-linked cluster with broad espionage and financially motivated activity. Commonly tied to Bangladesh Bank, WannaCry, crypto exchange thefts, and Dream Job style campaigns.",
        "sources": ["CISA AA22-110A"],
    },
    {
        "canonical_name": "APT41",
        "aliases": ["Double Dragon", "Barium", "Wicked Panda", "Winnti", "BARIUM"],
        "kind": "actor",
        "description": "Chinese cluster associated with dual-mission operations. Known for supply-chain targeting, mobile malware, and gaming-sector intrusions.",
        "sources": [],
    },
    {
        "canonical_name": "FIN7",
        "aliases": ["Carbanak", "Carbanak Group", "FIN7", "Cobalt Group", "Grim Spider"],
        "kind": "actor",
        "description": "Financially motivated operator cluster with major theft history. Commonly associated with Carbanak malware and extensive retail/hospitality targeting.",
        "sources": [],
    },
    {
        "canonical_name": "Sandworm",
        "aliases": ["IRIDIUM", "ELECTRUM", "Telebots", "Voodoo Bear", "Hafnium", "FROZEN LAKE", "Seashell Blizzard"],
        "kind": "actor",
        "description": "GRU Unit 74455. Known for destructive operations, Ukraine-related attacks, and the NotPetya ecosystem. Capture grid disruption, wiper behavior, and newer malware such as AcidPour.",
        "sources": ["CISA AA24-249A"],
    },
    {
        "canonical_name": "Turla",
        "aliases": ["Snake", "KRYPTON", "Venomous Bear", "Secret Blizzard", "Kapa"],
        "kind": "actor",
        "description": "FSB-linked operations. Known for unusual infrastructure, including satellite-based C2 concepts. Older lineage, malware succession, and long-lived espionage operations.",
        "sources": [],
    },
    {
        "canonical_name": "Equation Group",
        "aliases": ["Equation Group", "EQGRP"],
        "kind": "actor",
        "description": "Frequently linked in public reporting to NSA TAO. Historically associated with advanced implants, firmware targeting, and Shadow Brokers leaks.",
        "sources": [],
    },
    {
        "canonical_name": "Evil Corp",
        "aliases": ["Indrik Spider", "Spiderweb", "UNC2165"],
        "kind": "actor",
        "description": "Commonly associated with Dridex, BitPaymer, and other financially motivated activity. Sanctions-related context, affiliate relationships, and malware reuse.",
        "sources": [],
    },
    {
        "canonical_name": "LockBit",
        "aliases": ["LockBit 2.0", "LockBit 3.0", "ABCD", "LockBit Black", "LockBitSupp", "Dmitry Khoroshev"],
        "kind": "actor",
        "description": "One of the most visible ransomware-as-a-service operations of 2022-2023. Affiliate program features, support-chat behavior, and leak-site lifecycle.",
        "sources": ["CISA AA23-325A"],
    },
    {
        "canonical_name": "BlackCat",
        "aliases": ["ALPHV", "ALPHV/BlackCat", "Noberus"],
        "kind": "actor",
        "description": "Rust-based ransomware group known for triple extortion framing. Seizure events, rebranding behavior, and comeback narratives.",
        "sources": [],
    },
    {
        "canonical_name": "Conti",
        "aliases": ["Conti", "Ryuk", "TrickBot"],
        "kind": "actor",
        "description": "Known for leaked chats and heavy operational visibility. Connections to TrickBot, Ryuk lineage, and public-sector impacts.",
        "sources": [],
    },
    {
        "canonical_name": "Cl0p",
        "aliases": ["TA505", "Cl0p", "Cloaked Ursa", "FIN11"],
        "kind": "actor",
        "description": "Known for mass exploitation of file transfer and managed service products. MOVEit, Accellion, and GoAnywhere style campaigns.",
        "sources": ["CISA AA23-158A"],
    },
    {
        "canonical_name": "Play",
        "aliases": ["Play", "PlayCrypt"],
        "kind": "actor",
        "description": "Volume-driven ransomware group with ESXi and enterprise-targeting behavior. Victim counts, sector focus, and common initial access vectors.",
        "sources": ["CISA AA23-352A"],
    },
    {
        "canonical_name": "Akira",
        "aliases": ["Akira", "Megazord"],
        "kind": "actor",
        "description": "Linux and VMware-targeting ransomware family and operation set. VPN exploitation, double extortion, and environment-specific abuse.",
        "sources": ["CISA AA24-109A"],
    },
]

# ── Ransomware families with detailed CISA advisory links ─────────────────────

RANSOMWARE_FAMILIES = [
    {"name": "RansomHub", "advisory": "CISA AA24-242A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"},
    {"name": "Medusa", "advisory": "CISA AA25-071A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a"},
    {"name": "Rhysida", "advisory": "CISA AA23-319A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a"},
    {"name": "BianLian", "advisory": "CISA AA23-136A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a"},
    {"name": "Royal", "advisory": "CISA AA23-061A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a"},
    {"name": "Vice Society", "advisory": "CISA AA22-249A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-249a"},
    {"name": "MedusaLocker", "advisory": "CISA AA22-181A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-181a"},
]

# ── DLLs ──────────────────────────────────────────────────────────────────────

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

# ── Source URLs for feed tracking ────────────────────────────────────────────

FEED_SOURCES = [
    {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "title": "NVD CVE Feed", "kind": "api", "source_type": "nvd"},
    {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "title": "CISA KEV Feed", "kind": "feed", "source_type": "json"},
    {"https://api.github.com/advisories", "title": "GitHub Security Advisories", "kind": "api", "source_type": "github"},
    {"https://ransomwatch.telemetry.ltd/feed/v1", "title": "Ransomwatch Feed", "kind": "feed", "source_type": "rss"},
    {"https://api.ransomfeed.it/v1/stats", "title": "Ransomfeed Stats", "kind": "api", "source_type": "json"},
]


async def seed(db_url: str, tenant_id: uuid.UUID) -> dict:
    """Seed knowledge from knowledge.md into the database."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select, text

    engine = create_async_engine(db_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    stats = {"actors": 0, "aliases": 0, "families": 0, "dlls": 0, "lolbins": 0, "feeds": 0}

    async with async_session() as db:
        # ── Threat Actors ──
        for actor in THREAT_ACTORS:
            # Check if entity exists
            existing = await db.execute(
                text("SELECT id FROM entities WHERE canonical_name = :name AND kind = 'actor' AND tenant_id = :tid"),
                {"name": actor["canonical_name"], "tid": tenant_id}
            )
            row = existing.first()
            if row:
                entity_id = row[0]
            else:
                entity_id = uuid.uuid4()
                await db.execute(text(
                    """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                       VALUES (:id, :tid, 'actor', :name, :refs::jsonb)"""
                ), {
                    "id": entity_id, "tid": tenant_id, "name": actor["canonical_name"],
                    "refs": f'{{"description": {repr(actor["description"])}, "sources": {repr(actor["sources"])}}}'
                })
                stats["actors"] += 1

            # Add aliases
            for alias in actor["aliases"]:
                existing_alias = await db.execute(
                    text("SELECT id FROM entity_aliases WHERE entity_id = :eid AND alias = :alias"),
                    {"eid": entity_id, "alias": alias}
                )
                if not existing_alias.first():
                    await db.execute(text(
                        """INSERT INTO entity_aliases (id, entity_id, alias, tenant_id)
                           VALUES (:id, :eid, :alias, :tid)"""
                    ), {"id": uuid.uuid4(), "eid": entity_id, "alias": alias, "tid": tenant_id})
                    stats["aliases"] += 1

        # ── Ransomware Families ──
        for fam in RANSOMWARE_FAMILIES:
            existing = await db.execute(
                text("SELECT id FROM entities WHERE canonical_name = :name AND kind = 'malware' AND tenant_id = :tid"),
                {"name": fam["name"], "tid": tenant_id}
            )
            if not existing.first():
                await db.execute(text(
                    """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                       VALUES (:id, :tid, 'malware', :name, :refs::jsonb)"""
                ), {
                    "id": uuid.uuid4(), "tid": tenant_id, "name": fam["name"],
                    "refs": f'{{"advisory": "{fam["advisory"]}", "url": "{fam["url"]}"}}'
                })
                stats["families"] += 1

        # ── DLLs ──
        for dll in CORE_DLLS + SYSTEM_PROCESSES:
            existing = await db.execute(
                text("SELECT id FROM entities WHERE canonical_name = :name AND kind = 'tool' AND tenant_id = :tid"),
                {"name": dll, "tid": tenant_id}
            )
            if not existing.first():
                await db.execute(text(
                    """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                       VALUES (:id, :tid, 'tool', :name, '{{\"category\": \"dll\"}}'::jsonb)"""
                ), {"id": uuid.uuid4(), "tid": tenant_id, "name": dll})
                stats["dlls"] += 1

        # ── LOLBINs ──
        for lolbin in LOLBINS:
            existing = await db.execute(
                text("SELECT id FROM entities WHERE canonical_name = :name AND kind = 'tool' AND tenant_id = :tid"),
                {"name": lolbin, "tid": tenant_id}
            )
            if not existing.first():
                await db.execute(text(
                    """INSERT INTO entities (id, tenant_id, kind, canonical_name, external_refs)
                       VALUES (:id, :tid, 'tool', :name, '{{\"category\": \"lolbin\"}}'::jsonb)"""
                ), {"id": uuid.uuid4(), "tid": tenant_id, "name": lolbin})
                stats["lolbins"] += 1

        # ── Feed Sources ──
        for src in FEED_SOURCES:
            existing = await db.execute(
                text("SELECT id FROM source_records WHERE url = :url AND tenant_id = :tid"),
                {"url": src["url"], "tid": tenant_id}
            )
            if not existing.first():
                await db.execute(text(
                    """INSERT INTO source_records (id, tenant_id, url, title, kind, source_type, active, fetch_interval_seconds)
                       VALUES (:id, :tid, :url, :title, :kind, :stype, true, 1200)"""
                ), {
                    "id": uuid.uuid4(), "tid": tenant_id, "url": src["url"],
                    "title": src["title"], "kind": src["kind"], "stype": src["source_type"],
                })
                stats["feeds"] += 1

        await db.commit()

    await engine.dispose()
    return stats


if __name__ == "__main__":
    import os
    db_url = os.environ.get("DATABASE_URL", "postgresql+asyncpg://sk:sk@localhost/sk")
    # Default tenant from bootstrap
    result = asyncio.run(seed(db_url, uuid.UUID("00000000-0000-0000-0000-000000000000")))
    print(f"Seeded: {result}")
