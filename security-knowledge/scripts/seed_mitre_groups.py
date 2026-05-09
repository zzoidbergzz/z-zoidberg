#!/usr/bin/env python3
"""Seed MITRE ATT&CK groups directly into the DB via asyncpg."""
import asyncio
import json
import os
import uuid

import asyncpg

DB_URL = os.environ.get("DATABASE_URL", "postgresql://sk:sk@localhost:5433/sk")
STIX_PATH = os.path.expanduser("~/.cache/sk-mitre-data/enterprise-attack.json")


def load_groups(stix_path: str) -> list[dict]:
    with open(stix_path) as f:
        bundle = json.load(f)
    groups = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break
        name = obj.get("name", "")
        description = (obj.get("description", "") or "")[:4000]
        aliases = [a for a in (obj.get("aliases", []) or []) if a != name]
        url = f"https://attack.mitre.org/groups/{attack_id}/" if attack_id else ""
        groups.append({
            "attack_id": attack_id,
            "name": name,
            "canonical_name": f"{attack_id} - {name}" if attack_id else name,
            "description": description,
            "aliases": aliases,
            "url": url,
        })
    return groups


async def main():
    if not os.path.exists(STIX_PATH):
        print(f"❌ STIX data not found at {STIX_PATH}")
        return
    groups = load_groups(STIX_PATH)
    print(f"📖 Loaded {len(groups)} MITRE ATT&CK groups")

    conn = await asyncpg.connect(DB_URL)
    try:
        row = await conn.fetchrow("SELECT id FROM tenants WHERE slug = 'default'")
        if not row:
            print("❌ No default tenant")
            return
        tenant_id = row["id"]

        inserted = 0
        updated = 0

        for g in groups:
            attack_id = g["attack_id"]
            existing = None

            # Match by mitre_attack_id
            if attack_id:
                existing = await conn.fetchrow(
                    "SELECT id FROM entities WHERE tenant_id = $1 AND mitre_attack_id = $2",
                    tenant_id, attack_id,
                )
            # Match by bare name (stub entities like "Scattered Spider")
            if not existing:
                existing = await conn.fetchrow(
                    "SELECT id FROM entities WHERE tenant_id = $1 AND canonical_name = $2",
                    tenant_id, g["name"],
                )
            # Fuzzy: name in canonical_name
            if not existing:
                existing = await conn.fetchrow(
                    "SELECT id FROM entities WHERE tenant_id = $1 AND canonical_name ILIKE $2",
                    tenant_id, f"%{g['name']}%",
                )

            refs = json.dumps({
                "mitre_attack": attack_id,
                "mitre_url": g["url"],
                "description": g["description"],
            })

            if existing:
                eid = existing["id"]
                await conn.execute(
                    """UPDATE entities SET
                        mitre_attack_id = $2, canonical_name = $3,
                        external_refs = $4, kind = 'threat_actor', updated_at = now()
                    WHERE id = $1""",
                    eid, attack_id, g["canonical_name"], refs,
                )
                for alias in g["aliases"]:
                    await conn.execute(
                        """INSERT INTO entity_aliases (id, entity_id, alias, created_at, updated_at)
                        VALUES ($1, $2, $3, now(), now()) ON CONFLICT DO NOTHING""",
                        str(uuid.uuid4()), eid, alias,
                    )
                updated += 1
            else:
                eid = str(uuid.uuid4())
                await conn.execute(
                    """INSERT INTO entities
                    (id, tenant_id, kind, canonical_name, mitre_attack_id, external_refs, created_at, updated_at)
                    VALUES ($1, $2, 'threat_actor', $3, $4, $5, now(), now())""",
                    eid, tenant_id, g["canonical_name"], attack_id, refs,
                )
                for alias in g["aliases"]:
                    await conn.execute(
                        """INSERT INTO entity_aliases (id, entity_id, alias, created_at, updated_at)
                        VALUES ($1, $2, $3, now(), now()) ON CONFLICT DO NOTHING""",
                        str(uuid.uuid4()), eid, alias,
                    )
                inserted += 1

        print(f"✅ Done: {inserted} new, {updated} updated (of {len(groups)} groups)")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
