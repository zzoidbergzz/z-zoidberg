"""Seed knowledge content into the Security Knowledge database.

Usage:
  python -m seed.seed_knowledge                # loads both (default)
  python -m seed.seed_knowledge --reverse-shells
  python -m seed.seed_knowledge --mitre
  python -m seed.seed_knowledge --all

The script is fully idempotent — safe to run repeatedly.
Requires: seed_data.py to have been run first (tenant + admin user must exist).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

logger = structlog.get_logger(__name__)

_UTC = timezone.utc


async def _get_or_create_tenant(db: AsyncSession):
    from app.models.auth import Tenant
    result = await db.execute(select(Tenant).where(Tenant.slug == "default"))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        print("ERROR: default tenant not found. Run `python -m seed.seed_data` first.", file=sys.stderr)
        sys.exit(1)
    return tenant


async def _upsert_source(db: AsyncSession, tenant_id, source_dict: dict):
    from app.models.sources import SourceRecord
    result = await db.execute(select(SourceRecord).where(SourceRecord.url == source_dict["url"], SourceRecord.tenant_id == tenant_id))
    existing = result.scalar_one_or_none()
    if existing:
        return existing
    record = SourceRecord(
        tenant_id=tenant_id,
        url=source_dict["url"],
        title=source_dict["title"],
        kind=source_dict["kind"],
        source_type=source_dict["source_type"],
        external_refs=source_dict.get("external_refs", {}),
        active=True,
    )
    db.add(record)
    await db.flush()
    return record


async def _upsert_entity(db: AsyncSession, tenant_id, edict: dict):
    from app.models.entities import Entity
    result = await db.execute(
        select(Entity).where(
            Entity.tenant_id == tenant_id,
            Entity.kind == edict["kind"],
            Entity.canonical_name == edict["canonical_name"],
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        # Refresh description + refs if provided
        if edict.get("description"):
            existing.description = edict["description"]
        if edict.get("external_refs"):
            existing.external_refs = {**existing.external_refs, **edict["external_refs"]}
        if edict.get("properties"):
            existing.properties = {**existing.properties, **edict["properties"]}
        if edict.get("stix_id"):
            existing.stix_id = edict["stix_id"]
        return existing, False
    entity = Entity(
        tenant_id=tenant_id,
        kind=edict["kind"],
        canonical_name=edict["canonical_name"],
        description=edict.get("description", ""),
        stix_id=edict.get("stix_id"),
        mitre_attack_id=edict.get("mitre_attack_id") or (edict.get("properties", {}).get("attack_id")),
        external_refs=edict.get("external_refs", {}),
        properties=edict.get("properties", {}),
    )
    db.add(entity)
    await db.flush()
    return entity, True


async def _upsert_claim(db: AsyncSession, tenant_id, entity_id, cdict: dict):
    from app.models.claims import Claim
    result = await db.execute(
        select(Claim).where(
            Claim.tenant_id == tenant_id,
            Claim.statement == cdict["statement"],
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        return existing, False
    claim = Claim(
        tenant_id=tenant_id,
        statement=cdict["statement"],
        claim_type=cdict.get("claim_type", "attack_technique"),
        confidence=cdict.get("confidence", 0.95),
        review_status="approved",
        tags=cdict.get("tags", []),
        properties={
            **cdict.get("properties", {}),
            "entity_id": str(entity_id),
        },
    )
    db.add(claim)
    await db.flush()
    return claim, True


async def seed_reverse_shells(db: AsyncSession):
    """Load reverse shell cheat-sheet knowledge corpus."""
    from seed.knowledge.reverse_shells import PARENT_ATTACK_PATTERN, SOURCE, TECHNIQUES

    tenant = await _get_or_create_tenant(db)
    tenant_id = tenant.id

    source = await _upsert_source(db, tenant_id, SOURCE)

    entities_created = 0
    claims_created = 0

    # Parent T1059 entity
    _, created = await _upsert_entity(db, tenant_id, PARENT_ATTACK_PATTERN)
    if created:
        entities_created += 1

    for item in TECHNIQUES:
        entity, created = await _upsert_entity(db, tenant_id, item["entity"])
        if created:
            entities_created += 1
        for cdict in item.get("claims", []):
            _, c_created = await _upsert_claim(db, tenant_id, entity.id, cdict)
            if c_created:
                claims_created += 1

    await db.commit()
    print(f"✅ Reverse Shells: {entities_created} new entities, {claims_created} new claims loaded.")
    return entities_created, claims_created


async def seed_mitre_attack(db: AsyncSession):
    """Import MITRE ATT&CK enterprise entities into the knowledge DB.

    Requires MITRE STIX data to be present. If not downloaded, attempts to
    download it first using mitreattack-python.
    """
    try:
        from mitreattack.stix20 import MitreAttackData
    except ImportError:
        print("⚠️  mitreattack-python not installed. Skipping MITRE seed. Run: pip install mitreattack-python", file=sys.stderr)
        return 0, 0

    import os
    from app.services import mitre_attack as ma_svc

    data_dir = ma_svc.get_data_dir()
    domain = "enterprise"
    stix_path = str(ma_svc._stix_file_path(domain))

    if not os.path.exists(stix_path):
        print(f"📥 Downloading MITRE ATT&CK STIX data to {data_dir} ...")
        try:
            import asyncio
            asyncio.get_event_loop().run_until_complete(ma_svc.ensure_data_downloaded(domain))
        except Exception as e:
            print(f"❌ MITRE download failed: {e}", file=sys.stderr)
            return 0, 0

    print(f"📖 Loading MITRE ATT&CK data from {stix_path} ...")
    try:
        attack_data = MitreAttackData(stix_path)
    except Exception as e:
        print(f"❌ Failed to load STIX data: {e}", file=sys.stderr)
        return 0, 0

    tenant = await _get_or_create_tenant(db)
    tenant_id = tenant.id

    entities_created = 0
    skipped = 0

    # Helper to get ATT&CK ID from external refs
    def get_attack_id(obj) -> str | None:
        for ref in getattr(obj, "external_references", []) or []:
            if hasattr(ref, "source_name") and ref.source_name == "mitre-attack":
                return getattr(ref, "external_id", None)
        return None

    def obj_to_dict(obj, kind: str) -> dict:
        attack_id = get_attack_id(obj)
        name = getattr(obj, "name", "")
        description = getattr(obj, "description", "") or ""
        tactics = [p.phase_name for p in (getattr(obj, "kill_chain_phases", []) or [])]
        platforms = list(getattr(obj, "x_mitre_platforms", []) or [])
        return {
            "kind": kind,
            "canonical_name": f"{attack_id} - {name}" if attack_id else name,
            "description": description[:2000],
            "stix_id": obj.id,
            "external_refs": {
                "mitre_attack": attack_id,
                "mitre_url": f"https://attack.mitre.org/techniques/{attack_id}/" if attack_id else "",
            },
            "properties": {
                "attack_id": attack_id,
                "platforms": platforms,
                "tactics": tactics,
                "is_subtechnique": getattr(obj, "x_mitre_is_subtechnique", False),
                "deprecated": getattr(obj, "x_mitre_deprecated", False),
                "revoked": getattr(obj, "revoked", False),
            },
        }

    # Techniques (including subtechniques)
    print("  Loading techniques...")
    all_techniques = attack_data.get_techniques(include_subtechniques=True)
    for t in all_techniques:
        if getattr(t, "revoked", False):
            skipped += 1
            continue
        edict = obj_to_dict(t, "attack_pattern")
        _, created = await _upsert_entity(db, tenant_id, edict)
        if created:
            entities_created += 1

    await db.flush()

    # Groups (intrusion-sets)
    print("  Loading threat actors/groups...")
    all_groups = attack_data.get_groups()
    for g in all_groups:
        if getattr(g, "revoked", False):
            skipped += 1
            continue
        attack_id = get_attack_id(g)
        edict = {
            "kind": "actor",
            "canonical_name": f"{attack_id} - {g.name}" if attack_id else g.name,
            "description": (getattr(g, "description", "") or "")[:2000],
            "stix_id": g.id,
            "external_refs": {"mitre_attack": attack_id},
            "properties": {
                "attack_id": attack_id,
                "aliases": list(getattr(g, "aliases", []) or []),
            },
        }
        _, created = await _upsert_entity(db, tenant_id, edict)
        if created:
            entities_created += 1

    await db.flush()

    # Software (malware + tools)
    print("  Loading software (malware/tools)...")
    all_software = attack_data.get_software()
    for s in all_software:
        if getattr(s, "revoked", False):
            skipped += 1
            continue
        attack_id = get_attack_id(s)
        stix_type = getattr(s, "type", "tool")
        kind = "malware" if stix_type == "malware" else "tool"
        edict = {
            "kind": kind,
            "canonical_name": f"{attack_id} - {s.name}" if attack_id else s.name,
            "description": (getattr(s, "description", "") or "")[:2000],
            "stix_id": s.id,
            "external_refs": {"mitre_attack": attack_id},
            "properties": {
                "attack_id": attack_id,
                "platforms": list(getattr(s, "x_mitre_platforms", []) or []),
                "aliases": list(getattr(s, "x_mitre_aliases", []) or []),
            },
        }
        _, created = await _upsert_entity(db, tenant_id, edict)
        if created:
            entities_created += 1

    await db.flush()

    # Campaigns
    print("  Loading campaigns...")
    all_campaigns = attack_data.get_campaigns()
    for c in all_campaigns:
        if getattr(c, "revoked", False):
            skipped += 1
            continue
        attack_id = get_attack_id(c)
        edict = {
            "kind": "campaign",
            "canonical_name": f"{attack_id} - {c.name}" if attack_id else c.name,
            "description": (getattr(c, "description", "") or "")[:2000],
            "stix_id": c.id,
            "external_refs": {"mitre_attack": attack_id},
            "properties": {"attack_id": attack_id},
        }
        _, created = await _upsert_entity(db, tenant_id, edict)
        if created:
            entities_created += 1

    await db.commit()
    print(f"✅ MITRE ATT&CK Enterprise: {entities_created} new entities loaded ({skipped} revoked/skipped).")
    return entities_created, 0


async def main(run_reverse_shells: bool = True, run_mitre: bool = True) -> None:
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        if run_reverse_shells:
            print("\n── Reverse Shells Cheat Sheet ────────────────────────")
            await seed_reverse_shells(db)

        if run_mitre:
            print("\n── MITRE ATT&CK Enterprise ───────────────────────────")
            await seed_mitre_attack(db)

    await engine.dispose()
    print("\n✅ Knowledge seed complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed knowledge content into the SK database")
    parser.add_argument("--reverse-shells", action="store_true", help="Load reverse shells knowledge only")
    parser.add_argument("--mitre", action="store_true", help="Load MITRE ATT&CK data only")
    parser.add_argument("--all", action="store_true", help="Load everything (default)")
    args = parser.parse_args()

    run_rs = args.reverse_shells or args.all or not (args.reverse_shells or args.mitre)
    run_m = args.mitre or args.all or not (args.reverse_shells or args.mitre)

    asyncio.run(main(run_reverse_shells=run_rs, run_mitre=run_m))
