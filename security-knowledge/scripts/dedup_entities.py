"""Deduplicate and harmonise entities in the security knowledge database.

Usage:
    python -m scripts.dedup_entities

Merges duplicate entities (same actor, different canonical names) by:
1. Finding entities with matching aliases (e.g. multiple APT28s)
2. Merging claims, evidence, and relationships into the canonical entity
3. Reassigning aliases from duplicate → canonical
4. Deleting duplicates

Also normalises tags by consolidating similar tags.
"""
from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict

import structlog

logger = structlog.get_logger(__name__)

# ── Known deduplication mappings ─────────────────────────────────────────────
# Maps non-canonical names to their canonical entity name
DEDUP_MAP = {
    "APT28": "APT28",
    "Fancy Bear": "APT28",
    "Sofacy": "APT28",
    "Sednit": "APT28",
    "STRONTIUM": "APT28",
    "Pawn Storm": "APT28",
    "Iron Twilight": "APT28",
    "APT29": "APT29",
    "Cozy Bear": "APT29",
    "The Dukes": "APT29",
    "Dark Halo": "APT29",
    "Nobelium": "APT29",
    "UNC2452": "APT29",
    "Lazarus Group": "Lazarus Group",
    "HIDDEN COBRA": "Lazarus Group",
    "Guardians of Peace": "Lazarus Group",
    "Zinc": "Lazarus Group",
    "APT38": "Lazarus Group",
    "BlueNoroff": "Lazarus Group",
    "Andariel": "Lazarus Group",
    "APT41": "APT41",
    "Double Dragon": "APT41",
    "Barium": "APT41",
    "Wicked Panda": "APT41",
    "FIN7": "FIN7",
    "Carbanak": "FIN7",
    "Cobalt Group": "FIN7",
    "Sandworm": "Sandworm",
    "IRIDIUM": "Sandworm",
    "ELECTRUM": "Sandworm",
    "Telebots": "Sandworm",
    "Voodoo Bear": "Sandworm",
    "Seashell Blizzard": "Sandworm",
    "Turla": "Turla",
    "Snake": "Turla",
    "KRYPTON": "Turla",
    "Venomous Bear": "Turla",
    "Equation Group": "Equation Group",
    "Evil Corp": "Evil Corp",
    "Indrik Spider": "Evil Corp",
    "LockBit": "LockBit",
    "LockBit 2.0": "LockBit",
    "LockBit 3.0": "LockBit",
    "LockBit Black": "LockBit",
    "BlackCat": "BlackCat",
    "ALPHV": "BlackCat",
    "ALPHV/BlackCat": "BlackCat",
    "Conti": "Conti",
    "Cl0p": "Cl0p",
    "TA505": "Cl0p",
    "FIN11": "Cl0p",
    "Play": "Play",
    "PlayCrypt": "Play",
    "Akira": "Akira",
    "Megazord": "Akira",
    "Royal": "Royal",
    "BlackSuit": "Royal",
}


async def dedup(db_url: str, tenant_id: uuid.UUID) -> dict:
    """Deduplicate entities in the database."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select, text

    engine = create_async_engine(db_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    stats = {"merged": 0, "aliases_created": 0, "duplicates_removed": 0}

    async with async_session() as db:
        # Group actor entities by their canonical name using the dedup map
        entities = await db.execute(text(
            """SELECT id, canonical_name, kind FROM entities
               WHERE kind = 'actor' AND tenant_id = :tid"""
        ), {"tid": tenant_id})
        actors = entities.all()

        # Build groups: canonical_name → [entity_ids]
        groups = defaultdict(list)
        for eid, name, kind in actors:
            canonical = DEDUP_MAP.get(name, name)
            groups[canonical].append((eid, name))

        # For each group with >1 entity, merge into the first (canonical)
        for canonical_name, members in groups.items():
            if len(members) <= 1:
                continue

            # Find or create the canonical entity
            canonical_entity = await db.execute(text(
                """SELECT id FROM entities
                   WHERE canonical_name = :name AND kind = 'actor' AND tenant_id = :tid
                   LIMIT 1"""
            ), {"name": canonical_name, "tid": tenant_id})
            canon_row = canonical_entity.first()

            if not canon_row:
                logger.warning("dedup_no_canonical", name=canonical_name)
                continue

            canon_id = canon_row[0]

            for eid, name in members:
                if eid == canon_id:
                    continue

                # Migrate claims
                await db.execute(text(
                    "UPDATE claims SET entity_id = :canon WHERE entity_id = :dup"
                ), {"canon": canon_id, "dup": eid})

                # Migrate evidence
                await db.execute(text(
                    "UPDATE evidence SET entity_id = :canon WHERE entity_id = :dup"
                ), {"canon": canon_id, "dup": eid})

                # Migrate relationships
                await db.execute(text(
                    "UPDATE relationships SET from_entity_id = :canon WHERE from_entity_id = :dup"
                ), {"canon": canon_id, "dup": eid})
                await db.execute(text(
                    "UPDATE relationships SET to_entity_id = :canon WHERE to_entity_id = :dup"
                ), {"canon": canon_id, "dup": eid})

                # Migrate aliases from duplicate to canonical
                await db.execute(text(
                    "UPDATE entity_aliases SET entity_id = :canon WHERE entity_id = :dup"
                ), {"canon": canon_id, "dup": eid})

                # Add the duplicate's name as an alias
                existing_alias = await db.execute(text(
                    """SELECT id FROM entity_aliases
                       WHERE entity_id = :canon AND alias = :alias"""
                ), {"canon": canon_id, "alias": name})
                if not existing_alias.first():
                    await db.execute(text(
                        """INSERT INTO entity_aliases (id, entity_id, alias)
                           VALUES (:id, :canon, :alias)"""
                    ), {"id": uuid.uuid4(), "canon": canon_id, "alias": name})
                    stats["aliases_created"] += 1

                # Delete the duplicate entity
                await db.execute(text(
                    "DELETE FROM entities WHERE id = :dup"
                ), {"dup": eid})
                stats["duplicates_removed"] += 1

            stats["merged"] += 1
            logger.info("dedup_merged", canonical=canonical_name, merged_count=len(members) - 1)

        await db.commit()

    await engine.dispose()
    return stats


if __name__ == "__main__":
    import os
    db_url = os.environ.get("DATABASE_URL", "postgresql+asyncpg://sk:sk@localhost/sk")
    result = asyncio.run(dedup(db_url, uuid.UUID("00000000-0000-0000-0000-000000000000")))
    print(f"Dedup result: {result}")
