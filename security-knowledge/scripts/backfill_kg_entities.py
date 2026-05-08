#!/usr/bin/env python
"""Backfill knowledge-graph entities from the curated entity catalog.

For each entity row whose external_refs.knowledge_id matches an entry in
seed/knowledge/entity_catalog.yml:
  * canonical_name → friendly name (e.g. "SSVC")
  * kind            → typed (framework / tool / product / data_component / ...)
  * external_refs.description → short paragraph
  * external_refs.aka         → known synonyms
  * external_refs.url         → upstream link
  * external_refs.stub        → removed

Idempotent. Run any time.

    python scripts/backfill_kg_entities.py            # dry run
    python scripts/backfill_kg_entities.py --apply    # write changes
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
from pathlib import Path

import yaml
from sqlalchemy import text

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.database import AsyncSessionLocal  # noqa: E402

CATALOG_PATH = ROOT / "seed" / "knowledge" / "entity_catalog.yml"


def load_catalog() -> dict[str, dict]:
    with CATALOG_PATH.open() as f:
        return yaml.safe_load(f) or {}


async def backfill(apply: bool) -> int:
    catalog = load_catalog()
    print(f"loaded {len(catalog)} catalog entries from {CATALOG_PATH}")
    changed = 0
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                text(
                    "SELECT id, canonical_name, kind, external_refs"
                    " FROM entities WHERE external_refs ? 'knowledge_id'"
                )
            )
        ).all()
        print(f"scanning {len(rows)} entities with knowledge_id …")
        for eid, name, kind, refs in rows:
            kid = (refs or {}).get("knowledge_id")
            entry = catalog.get(kid)
            if not entry:
                continue
            new_refs = dict(refs or {})
            new_refs.pop("stub", None)
            for k in ("description", "aka", "url"):
                if entry.get(k) is not None:
                    val = entry[k]
                    if isinstance(val, str):
                        val = " ".join(val.split())
                    new_refs[k] = val
            new_kind = entry.get("kind") or kind
            new_name = entry.get("name") or name
            if (new_name, new_kind, new_refs) == (name, kind, refs or {}):
                continue
            changed += 1
            print(
                f"  {kid}: {name!r}/{kind!r} → {new_name!r}/{new_kind!r}"
                f"  (+desc={'description' in new_refs})"
            )
            if apply:
                await db.execute(
                    text(
                        "UPDATE entities SET canonical_name=:n, kind=:k, external_refs=:r,"
                        " updated_at=NOW() WHERE id=:id"
                    ),
                    {
                        "n": new_name,
                        "k": new_kind,
                        "r": json.dumps(new_refs),
                        "id": eid,
                    },
                )
        if apply:
            await db.commit()
    verb = "updated" if apply else "would update"
    print(f"{verb} {changed} entities")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = p.parse_args()
    sys.exit(asyncio.run(backfill(args.apply)))
