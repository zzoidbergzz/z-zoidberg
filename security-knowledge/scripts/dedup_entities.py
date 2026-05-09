"""Deduplicate and harmonise entities in the security knowledge database.

Usage:
    python scripts/dedup_entities.py

Requirements: pip install asyncpg

Merges duplicate entities (same actor, different canonical names) by:
1. Finding entities with matching aliases (e.g. multiple APT28s)
2. Merging claims, evidence, and relationships into the canonical entity
3. Reassigning aliases from duplicate → canonical
4. Deleting duplicates
"""
from __future__ import annotations

import asyncio
import os
import uuid
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

DB_URL = os.environ.get("DATABASE_URL", "postgresql://sk:sk@localhost:5432/sk")
DB_URL = DB_URL.replace("postgresql+asyncpg://", "postgresql://")
TENANT_ID = os.environ.get("TENANT_ID", "00000000-0000-0000-0000-000000000000")

# Maps non-canonical names to their canonical entity name
DEDUP_MAP = {
    "Fancy Bear": "APT28", "Sofacy": "APT28", "Sednit": "APT28",
    "STRONTIUM": "APT28", "Pawn Storm": "APT28", "Iron Twilight": "APT28",
    "Cozy Bear": "APT29", "The Dukes": "APT29", "Dark Halo": "APT29",
    "Nobelium": "APT29", "UNC2452": "APT29",
    "HIDDEN COBRA": "Lazarus Group", "Zinc": "Lazarus Group",
    "APT38": "Lazarus Group", "BlueNoroff": "Lazarus Group", "Andariel": "Lazarus Group",
    "Double Dragon": "APT41", "Barium": "APT41", "Wicked Panda": "APT41",
    "Carbanak": "FIN7", "Cobalt Group": "FIN7",
    "IRIDIUM": "Sandworm", "ELECTRUM": "Sandworm", "Telebots": "Sandworm",
    "Voodoo Bear": "Sandworm", "Seashell Blizzard": "Sandworm",
    "Snake": "Turla", "KRYPTON": "Turla", "Venomous Bear": "Turla",
    "Indrik Spider": "Evil Corp", "UNC2165": "Evil Corp",
    "LockBit 2.0": "LockBit", "LockBit 3.0": "LockBit", "LockBit Black": "LockBit",
    "ALPHV": "BlackCat", "ALPHV/BlackCat": "BlackCat", "Noberus": "BlackCat",
    "Ryuk": "Conti", "TrickBot": "Conti",
    "TA505": "Cl0p", "FIN11": "Cl0p",
    "PlayCrypt": "Play",
    "Megazord": "Akira",
    "BlackSuit": "Royal",
}


async def dedup() -> dict:
    import asyncpg

    conn = await asyncpg.connect(DB_URL)
    tid = uuid.UUID(TENANT_ID)
    stats = {"merged": 0, "aliases_created": 0, "duplicates_removed": 0}

    # Get all actor entities
    rows = await conn.fetch(
        "SELECT id, canonical_name FROM entities WHERE kind = 'actor' AND tenant_id = $1", tid,
    )

    # Group by canonical name
    groups = defaultdict(list)
    for r in rows:
        eid = r["id"]
        name = r["canonical_name"]
        canonical = DEDUP_MAP.get(name, name)
        groups[canonical].append((eid, name))

    for canonical_name, members in groups.items():
        if len(members) <= 1:
            continue

        # Find canonical entity
        canon_id = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND kind = 'actor' AND tenant_id = $2 LIMIT 1",
            canonical_name, tid,
        )
        if not canon_id:
            logger.warning(f"No canonical entity for {canonical_name}")
            continue

        for eid, name in members:
            if eid == canon_id:
                continue

            # Migrate claims
            await conn.execute("UPDATE claims SET entity_id = $1 WHERE entity_id = $2", canon_id, eid)
            # Migrate evidence
            await conn.execute("UPDATE evidence SET entity_id = $1 WHERE entity_id = $2", canon_id, eid)
            # Migrate relationships
            await conn.execute("UPDATE relationships SET from_entity_id = $1 WHERE from_entity_id = $2", canon_id, eid)
            await conn.execute("UPDATE relationships SET to_entity_id = $1 WHERE to_entity_id = $2", canon_id, eid)
            # Migrate aliases
            await conn.execute("UPDATE entity_aliases SET entity_id = $1 WHERE entity_id = $2", canon_id, eid)

            # Add duplicate's name as alias
            existing = await conn.fetchval(
                "SELECT id FROM entity_aliases WHERE entity_id = $1 AND alias = $2", canon_id, name,
            )
            if not existing:
                await conn.execute(
                    "INSERT INTO entity_aliases (id, entity_id, alias) VALUES ($1, $2, $3)",
                    uuid.uuid4(), canon_id, name,
                )
                stats["aliases_created"] += 1

            # Delete duplicate
            await conn.execute("DELETE FROM entities WHERE id = $1", eid)
            stats["duplicates_removed"] += 1
            logger.info(f"Merged {name} → {canonical_name}")

        stats["merged"] += 1

    await conn.close()
    return stats


if __name__ == "__main__":
    result = asyncio.run(dedup())
    print(f"Dedup result: {result}")
