"""Post-enrichment graph materializer.

After an enrichment provider returns data, this module turns the structured
results into claims, relationships, and linked entities — so that the
knowledge graph is populated with meaningful cross-references and pivots.

Currently handles:
  - VirusTotal file (hash) enrichment → malware families, alt hashes,
    dropped files, contacted IPs, ATT&CK techniques, CAPA signatures
  - VirusTotal IP/domain enrichment → geo, ASN, WHOIS, related URLs
  - MalwareBazaar hash enrichment → signatures, tags, reporter
  - Shodan IP enrichment → ports, banners, CVEs

Design: idempotent — re-running won't create duplicates because it uses
ON CONFLICT DO NOTHING for entities and checks for existing claims before
inserting.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.claims import Claim
from app.models.entities import Entity
from app.models.relationships import Relationship
from app.models.enrichment import EnrichmentCache

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map VT popular_threat_name → EntityKind.malware
_MALWARE_KIND = "malware"


async def _ensure_entity(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    kind: str,
    canonical_name: str,
    external_refs: dict | None = None,
) -> Entity:
    """Upsert entity — returns existing or newly created Entity.

    Uses ON CONFLICT DO UPDATE (no-op update) to atomically return the
    surviving row regardless of race conditions.
    """
    stmt = (
        pg_insert(Entity.__table__)
        .values(
            tenant_id=tenant_id,
            kind=kind,
            canonical_name=canonical_name,
            external_refs=external_refs or {},
        )
        .on_conflict_do_update(
            index_elements=["tenant_id", "kind", "canonical_name"],
            set_={"updated_at": func.now()},
        )
        .returning(Entity.__table__.c.id)
    )
    result = await db.execute(stmt)
    entity_id = result.scalar_one()
    # Fetch the full ORM object
    return (await db.execute(select(Entity).where(Entity.id == entity_id))).scalar_one()


async def _add_claim(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    entity_id: uuid.UUID,
    claim_type: str,
    value: dict,
    confidence: float = 1.0,
    status: str = "confirmed",
    external_refs: dict | None = None,
) -> Claim | None:
    """Add a claim if one of the same type doesn't already exist for this entity."""
    existing = await db.execute(
        select(Claim).where(
            Claim.tenant_id == tenant_id,
            Claim.entity_id == entity_id,
            Claim.claim_type == claim_type,
        )
    )
    if existing.scalar_one_or_none() is not None:
        return None

    claim = Claim(
        tenant_id=tenant_id,
        entity_id=entity_id,
        claim_type=claim_type,
        value=value,
        confidence=confidence,
        status=status,
        external_refs=external_refs or {},
    )
    db.add(claim)
    await db.flush()
    return claim


async def _add_relationship(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    from_entity_id: uuid.UUID,
    to_entity_id: uuid.UUID,
    kind: str,
    confidence: float = 1.0,
) -> Relationship | None:
    """Add a relationship if one of the same kind between the same pair doesn't exist."""
    existing = await db.execute(
        select(Relationship).where(
            Relationship.tenant_id == tenant_id,
            Relationship.from_entity_id == from_entity_id,
            Relationship.to_entity_id == to_entity_id,
            Relationship.kind == kind,
        )
    )
    if existing.scalar_one_or_none() is not None:
        return None

    rel = Relationship(
        tenant_id=tenant_id,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        kind=kind,
        confidence=confidence,
    )
    db.add(rel)
    await db.flush()
    return rel


# ---------------------------------------------------------------------------
# VirusTotal file (hash) materializer
# ---------------------------------------------------------------------------

async def materialize_vt_file(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    vt_data: dict,
) -> int:
    """Turn VT file enrichment data into graph elements. Returns items created."""
    created = 0
    value = entity.canonical_name

    # --- Claims ---

    # Detection stats
    if vt_data.get("malicious") is not None:
        c = await _add_claim(
            db, tenant_id, entity.id, "virus_total_detection",
            {
                "malicious": vt_data.get("malicious", 0),
                "suspicious": vt_data.get("suspicious", 0),
                "undetected": vt_data.get("undetected", 0),
                "harmless": vt_data.get("harmless", 0),
                "timeout": vt_data.get("timeout", 0),
                "detection_rate": f"{vt_data.get('malicious', 0)}/{vt_data.get('malicious', 0) + vt_data.get('suspicious', 0) + vt_data.get('undetected', 0) + vt_data.get('harmless', 0) + vt_data.get('timeout', 0)}",
                "suggested_label": (vt_data.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
            },
            confidence=1.0,
            external_refs={"source": "virustotal", "vt_link": vt_data.get("vt_link", "")},
        )
        if c:
            created += 1

    # File metadata
    if vt_data.get("file_type") or vt_data.get("file_size"):
        c = await _add_claim(
            db, tenant_id, entity.id, "file_metadata",
            {
                "filename": vt_data.get("meaningful_name", ""),
                "file_type": vt_data.get("file_type", ""),
                "file_size": vt_data.get("file_size"),
                "names": vt_data.get("names", [])[:10],
            },
            confidence=1.0,
            external_refs={"source": "virustotal"},
        )
        if c:
            created += 1

    # Hash cross-refs
    md5 = vt_data.get("md5", "")
    sha1 = vt_data.get("sha1", "")
    sha256 = vt_data.get("sha256", "")
    ssdeep = vt_data.get("ssdeep", "")
    tlsh = vt_data.get("tlsh", "")
    if md5 or sha1:
        c = await _add_claim(
            db, tenant_id, entity.id, "hash_cross_refs",
            {
                "sha256": sha256,
                "sha1": sha1,
                "md5": md5,
                "ssdeep": ssdeep,
                "tlsh": tlsh,
            },
            confidence=1.0,
            external_refs={"source": "virustotal"},
        )
        if c:
            created += 1

    # Threat classification
    ptc = vt_data.get("popular_threat_classification") or {}
    if ptc:
        c = await _add_claim(
            db, tenant_id, entity.id, "threat_classification",
            {
                "suggested_label": ptc.get("suggested_threat_label", ""),
                "categories": [{"name": x.get("value"), "count": x.get("count")} for x in ptc.get("popular_threat_category", [])],
                "threat_names": [{"name": x.get("value"), "count": x.get("count")} for x in ptc.get("popular_threat_name", [])],
            },
            confidence=0.95,
            external_refs={"source": "virustotal"},
        )
        if c:
            created += 1

    # --- Relationships ---

    # Alt hash entities (MD5, SHA1) → same_sample
    if md5:
        alt = await _ensure_entity(db, tenant_id, "hash", md5, {"hash_type": "md5", "sha256": sha256})
        r = await _add_relationship(db, tenant_id, entity.id, alt.id, "same_sample", 1.0)
        if r:
            created += 1

    if sha1:
        alt = await _ensure_entity(db, tenant_id, "hash", sha1, {"hash_type": "sha1", "sha256": sha256})
        r = await _add_relationship(db, tenant_id, entity.id, alt.id, "same_sample", 1.0)
        if r:
            created += 1

    # Malware family entities from popular_threat_name
    for threat in (ptc.get("popular_threat_name") or [])[:5]:
        family_name = threat.get("value", "").strip()
        if not family_name or family_name.lower() in ("unknown", "malicious", "malware", "trojan", "virus"):
            # Too generic — link to the more specific family if available
            continue
        family = await _ensure_entity(
            db, tenant_id, _MALWARE_KIND, family_name,
            {
                "family_type": next(
                    (c["value"] for c in (ptc.get("popular_threat_category") or []) if c.get("value")),
                    "malware"
                ),
                "categories": [c.get("value") for c in (ptc.get("popular_threat_category") or [])],
            },
        )
        r = await _add_relationship(db, tenant_id, entity.id, family.id, "is_sample_of", 0.9)
        if r:
            created += 1

    # Contacted IPs (from enrichment cache if available)
    # We don't get contacted IPs in the basic VT file response,
    # but if the cache has them (from a prior extended lookup), use them.
    contacted_ips = (vt_data.get("_contacted_ips") or [])
    for ip_val in contacted_ips:
        ip = await _ensure_entity(db, tenant_id, "ip_address", ip_val, {})
        r = await _add_relationship(db, tenant_id, entity.id, ip.id, "communicates_with", 0.85)
        if r:
            created += 1

    # Dropped files (from enrichment cache if available)
    dropped = (vt_data.get("_dropped_files") or [])
    for drop_sha256 in dropped:
        drop_ent = await _ensure_entity(
            db, tenant_id, "hash", drop_sha256,
            {"hash_type": "sha256", "relationship": "dropped_by", "parent_sha256": sha256},
        )
        r = await _add_relationship(db, tenant_id, entity.id, drop_ent.id, "drops", 0.9)
        if r:
            created += 1

    # ATT&CK techniques (from _capa_attack in extended enrichment)
    attack_techniques = (vt_data.get("_capa_attack") or [])
    for tech in attack_techniques:
        tech_id = tech.get("id", "")
        # Try to find existing ATT&CK entity by mitre_attack_id
        existing = await db.execute(
            select(Entity).where(
                Entity.tenant_id == tenant_id,
                Entity.kind == "attack_pattern",
                Entity.mitre_attack_id == tech_id,
            )
        )
        tech_ent = existing.scalar_one_or_none()
        if tech_ent:
            r = await _add_relationship(db, tenant_id, entity.id, tech_ent.id, "uses_technique", 0.9)
            if r:
                created += 1
            # Also link malware family → technique
            for threat in (ptc.get("popular_threat_name") or [])[:3]:
                family_name = threat.get("value", "").strip()
                if family_name and family_name.lower() not in ("unknown", "malicious", "malware"):
                    fam = await db.execute(
                        select(Entity).where(
                            Entity.tenant_id == tenant_id,
                            Entity.kind == _MALWARE_KIND,
                            Entity.canonical_name == family_name,
                        )
                    )
                    fam_ent = fam.scalar_one_or_none()
                    if fam_ent:
                        await _add_relationship(db, tenant_id, fam_ent.id, tech_ent.id, "uses_technique", 0.85)

    # Update entity external_refs with enrichment summary
    enrichment_summary = {
        "vt_last_enriched": datetime.now(UTC).isoformat()[:10],
        "vt_detection": f"{vt_data.get('malicious', '?')}/?",
        "vt_suggested_label": ptc.get("suggested_threat_label", ""),
    }
    if sha1:
        enrichment_summary["sha1"] = sha1
    if md5:
        enrichment_summary["md5"] = md5
    if ssdeep:
        enrichment_summary["ssdeep"] = ssdeep
    if tlsh:
        enrichment_summary["tlsh"] = tlsh

    entity.external_refs = {
        **(entity.external_refs or {}),
        "enrichment": enrichment_summary,
    }
    await db.flush()

    return created


# ---------------------------------------------------------------------------
# VirusTotal IP address materializer
# ---------------------------------------------------------------------------

async def materialize_vt_ip(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    vt_data: dict,
) -> int:
    """Turn VT IP enrichment into claims + relationships."""
    created = 0

    # Detection claim
    if vt_data.get("malicious") is not None:
        c = await _add_claim(
            db, tenant_id, entity.id, "virus_total_detection",
            {
                "malicious": vt_data.get("malicious", 0),
                "suspicious": vt_data.get("suspicious", 0),
                "harmless": vt_data.get("harmless", 0),
                "undetected": vt_data.get("undetected", 0),
            },
            confidence=1.0,
            external_refs={"source": "virustotal", "vt_link": vt_data.get("vt_link", "")},
        )
        if c:
            created += 1

    # Geo/ASN claim
    if vt_data.get("country") or vt_data.get("as_owner"):
        c = await _add_claim(
            db, tenant_id, entity.id, "geo_asn",
            {
                "country": vt_data.get("country"),
                "continent": vt_data.get("continent"),
                "as_owner": vt_data.get("as_owner"),
                "asn": vt_data.get("asn"),
                "network": vt_data.get("network"),
                "regional_internet_registry": vt_data.get("regional_internet_registry"),
            },
            confidence=1.0,
            external_refs={"source": "virustotal"},
        )
        if c:
            created += 1

    # ASN entity relationship
    if vt_data.get("asn") and vt_data.get("as_owner"):
        asn_ent = await _ensure_entity(
            db, tenant_id, "asn",
            f"AS{vt_data['asn']}",
            {"as_owner": vt_data["as_owner"], "country": vt_data.get("country", "")},
        )
        r = await _add_relationship(db, tenant_id, entity.id, asn_ent.id, "belongs_to_asn", 1.0)
        if r:
            created += 1

    return created


# ---------------------------------------------------------------------------
# VirusTotal domain materializer
# ---------------------------------------------------------------------------

async def materialize_vt_domain(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    vt_data: dict,
) -> int:
    """Turn VT domain enrichment into claims + relationships."""
    created = 0

    # Detection
    if vt_data.get("malicious") is not None:
        c = await _add_claim(
            db, tenant_id, entity.id, "virus_total_detection",
            {
                "malicious": vt_data.get("malicious", 0),
                "suspicious": vt_data.get("suspicious", 0),
                "harmless": vt_data.get("harmless", 0),
                "undetected": vt_data.get("undetected", 0),
            },
            confidence=1.0,
            external_refs={"source": "virustotal", "vt_link": vt_data.get("vt_link", "")},
        )
        if c:
            created += 1

    # WHOIS / registration
    if vt_data.get("registrar") or vt_data.get("creation_date"):
        c = await _add_claim(
            db, tenant_id, entity.id, "domain_registration",
            {
                "registrar": vt_data.get("registrar"),
                "creation_date": vt_data.get("creation_date"),
                "jarm": vt_data.get("jarm"),
            },
            confidence=1.0,
            external_refs={"source": "virustotal"},
        )
        if c:
            created += 1

    return created


# ---------------------------------------------------------------------------
# MalwareBazaar materializer
# ---------------------------------------------------------------------------

async def materialize_malwarebazaar(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    mb_data: dict,
) -> int:
    """Turn MalwareBazaar enrichment into claims + relationships."""
    created = 0
    mb = mb_data.get("malware_bazaar") or mb_data

    if not mb or not isinstance(mb, dict):
        return 0

    # Signature → malware family relationship
    signature = mb.get("signature", "").strip()
    if signature:
        c = await _add_claim(
            db, tenant_id, entity.id, "malware_bazaar_signature",
            {
                "signature": signature,
                "tags": mb.get("tags", [])[:20],
                "file_type": mb.get("file_type"),
                "file_size": mb.get("file_size"),
                "first_seen": mb.get("first_seen"),
                "mb_link": mb.get("mb_link"),
                "reporter": mb.get("reporter"),
            },
            confidence=1.0,
            external_refs={"source": "malwarebazaar"},
        )
        if c:
            created += 1

        # Create malware family entity
        family = await _ensure_entity(
            db, tenant_id, _MALWARE_KIND, signature,
            {"family_type": "malware", "source": "malwarebazaar", "tags": mb.get("tags", [])[:10]},
        )
        r = await _add_relationship(db, tenant_id, entity.id, family.id, "is_sample_of", 0.95)
        if r:
            created += 1

    # Cross-hash refs
    mb_sha256 = mb.get("sha256_hash", "")
    mb_md5 = mb.get("md5_hash", "")
    if mb_md5 and entity.canonical_name != mb_md5:
        alt = await _ensure_entity(db, tenant_id, "hash", mb_md5, {"hash_type": "md5", "sha256": mb_sha256})
        await _add_relationship(db, tenant_id, entity.id, alt.id, "same_sample", 1.0)

    return created


# ---------------------------------------------------------------------------
# Shodan materializer
# ---------------------------------------------------------------------------

async def materialize_shodan(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    shodan_data: dict,
) -> int:
    """Turn Shodan enrichment into claims + relationships."""
    created = 0

    if not shodan_data or not isinstance(shodan_data, dict):
        return 0

    # Port/ service claim
    ports = shodan_data.get("ports", [])
    if ports:
        c = await _add_claim(
            db, tenant_id, entity.id, "shodan_ports",
            {
                "ports": ports,
                "os": shodan_data.get("os"),
                "org": shodan_data.get("org"),
                "hostnames": shodan_data.get("hostnames", [])[:10],
                "last_seen": shodan_data.get("last_update"),
            },
            confidence=0.9,
            external_refs={"source": "shodan"},
        )
        if c:
            created += 1

    # CVEs found in banners
    vulns = shodan_data.get("vulns", [])
    if vulns:
        c = await _add_claim(
            db, tenant_id, entity.id, "shodan_vulnerabilities",
            {"cves": vulns[:20]},
            confidence=0.85,
            external_refs={"source": "shodan"},
        )
        if c:
            created += 1

        # Link CVE entities
        for cve_id in vulns[:10]:
            cve_ent = await _ensure_entity(db, tenant_id, "cve", cve_id, {})
            await _add_relationship(db, tenant_id, entity.id, cve_ent.id, "has_vulnerability", 0.8)

    return created


# ---------------------------------------------------------------------------
# Greynoise materializer
# ---------------------------------------------------------------------------

async def materialize_greynoise(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    gn_data: dict,
) -> int:
    """Turn Greynoise enrichment into claims + relationships."""
    created = 0

    if not gn_data or not isinstance(gn_data, dict):
        return 0

    c = await _add_claim(
        db, tenant_id, entity.id, "greynoise_classification",
        {
            "classification": gn_data.get("classification"),
            "name": gn_data.get("name"),
            "link": gn_data.get("link"),
            "noise": gn_data.get("noise"),
            "riot": gn_data.get("riot"),
            "message": gn_data.get("message"),
        },
        confidence=0.9,
        external_refs={"source": "greynoise"},
    )
    if c:
        created += 1

    # Link known actor if named
    actor_name = gn_data.get("name", "").strip()
    if actor_name and gn_data.get("classification") == "malicious":
        actor = await _ensure_entity(
            db, tenant_id, "actor", actor_name,
            {"source": "greynoise", "classification": "malicious"},
        )
        r = await _add_relationship(db, tenant_id, entity.id, actor.id, "associated_with_actor", 0.8)
        if r:
            created += 1

    return created


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PROVIDER_MATERIALIZERS = {
    "virustotal": {
        "hash": materialize_vt_file,
        "md5": materialize_vt_file,
        "sha1": materialize_vt_file,
        "sha256": materialize_vt_file,
        "ip": materialize_vt_ip,
        "ip_address": materialize_vt_ip,
        "domain": materialize_vt_domain,
        "hostname": materialize_vt_domain,
    },
    "malwarebazaar": {
        "hash": materialize_malwarebazaar,
        "md5": materialize_malwarebazaar,
        "sha1": materialize_malwarebazaar,
        "sha256": materialize_malwarebazaar,
        "malware": materialize_malwarebazaar,
    },
    "shodan": {
        "ip": materialize_shodan,
        "ip_address": materialize_shodan,
    },
    "greynoise": {
        "ip": materialize_greynoise,
        "ip_address": materialize_greynoise,
    },
    "otx": {
        "hash": materialize_malwarebazaar,
        "md5": materialize_malwarebazaar,
        "sha1": materialize_malwarebazaar,
        "sha256": materialize_malwarebazaar,
        "ip": materialize_vt_ip,
        "ip_address": materialize_vt_ip,
        "domain": materialize_vt_domain,
        "hostname": materialize_vt_domain,
    },
    "abuseipdb": {
        "ip": materialize_greynoise,
        "ip_address": materialize_greynoise,
    },
    "urlscan": {
        "ip": materialize_vt_ip,
        "ip_address": materialize_vt_ip,
        "domain": materialize_vt_domain,
        "hostname": materialize_vt_domain,
    },
}


async def materialize_enrichment(
    db: AsyncSession,
    entity: Entity,
    tenant_id: uuid.UUID,
    provider_name: str,
    enrichment_data: dict,
) -> int:
    """Dispatch to the correct materializer based on provider and entity kind.

    Returns the number of graph items created.
    """
    provider_map = _PROVIDER_MATERIALIZERS.get(provider_name, {})
    materializer = provider_map.get(entity.kind)

    if not materializer:
        logger.debug(
            "no_materializer",
            provider=provider_name,
            entity_kind=entity.kind,
        )
        return 0

    try:
        created = await materializer(db, entity, tenant_id, enrichment_data)
        if created:
            logger.info(
                "enrichment_materialized",
                provider=provider_name,
                entity_id=str(entity.id),
                entity_kind=entity.kind,
                items_created=created,
            )
        return created
    except Exception as exc:
        logger.warning(
            "enrichment_materializer_failed",
            provider=provider_name,
            entity_id=str(entity.id),
            error=str(exc),
        )
        return 0
