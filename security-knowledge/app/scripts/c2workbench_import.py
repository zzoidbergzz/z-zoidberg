#!/usr/bin/env python3
"""Import C2 frameworks from c2workbench.com API into z.je."""
import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

TENANT_ID = "bcc8ab78-0982-4ea3-81d3-7e4bd166881a"
C2WB_API = "https://www.c2workbench.com/api/frameworks"
REPOS_DIR = Path.home() / "repos" / "c2-frameworks"

async def main():
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(C2WB_API)
        frameworks = resp.json() if resp.status_code == 200 else []
    print(f"Fetched {len(frameworks)} frameworks")

    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPOS_DIR / "c2workbench_data.json", "w") as f:
        json.dump(frameworks, f, indent=2)
    print(f"Saved to {REPOS_DIR}/c2workbench_data.json")

    # Use raw asyncpg for JSON insertion
    import asyncpg
    conn = await asyncpg.connect("postgresql://sk:sk@localhost:5432/sk")

    imported = 0
    skipped = 0
    for fw in frameworks:
        name = fw.get("canonical_name", "")
        if not name:
            continue

        existing = await conn.fetchval(
            "SELECT id FROM entities WHERE canonical_name = $1 AND tenant_id = $2 AND kind = 'framework'",
            name, TENANT_ID
        )
        if existing:
            skipped += 1
            continue

        ext_refs = {
            "framework_type": fw.get("framework_type"),
            "description": fw.get("description", ""),
            "unique_description": fw.get("unique_description", ""),
            "primary_language": fw.get("primary_language"),
            "estimated_maturity": fw.get("estimated_maturity"),
            "supported_os": fw.get("supported_os") or [],
            "popularity_score": fw.get("popularity_score"),
            "capability_tags": (fw.get("capability_tags") or [])[:30],
            "c2wb_id": fw.get("id"),
            "source": "c2workbench",
            "c2wb_link": f"https://www.c2workbench.com/framework/{name}",
        }

        await conn.execute("""
            INSERT INTO entities (id, tenant_id, canonical_name, kind, external_refs, created_at, updated_at)
            VALUES (gen_random_uuid(), $1, $2, 'framework', $3::jsonb, now(), now())
        """, TENANT_ID, name, json.dumps(ext_refs))

        imported += 1

    await conn.close()
    print(f"Imported: {imported}, Skipped: {skipped}")

asyncio.run(main())
