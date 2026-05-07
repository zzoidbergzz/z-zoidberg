import uuid
from datetime import datetime, timezone
from app.stix.mapping import ENTITY_KIND_TO_STIX_TYPE, STIX_INDICATOR_PATTERNS


def _entity_name(entity) -> str:
    return getattr(entity, "name", None) or getattr(entity, "canonical_name", "?")


def build_stix_bundle(entities: list, claims: list, relationships: list | None = None) -> dict:
    """Build a STIX 2.1 Bundle from entities, claims, and optional relationship rows.

    Args:
        entities:      List of Entity ORM objects.
        claims:        List of Claim ORM objects (serialised as STIX notes).
        relationships: Optional list of Relationship ORM objects → STIX relationship objects.

    Returns:
        A dict that is a valid STIX 2.1 Bundle.
    """
    objects: list[dict] = []

    # ---------- Entities → STIX SDOs ----------
    for entity in entities:
        stix_type = ENTITY_KIND_TO_STIX_TYPE.get(entity.kind, "x-custom-object")
        name = _entity_name(entity)
        created = (
            entity.created_at.isoformat()
            if getattr(entity, "created_at", None)
            else datetime.now(timezone.utc).isoformat()
        )
        modified = (
            entity.updated_at.isoformat()
            if getattr(entity, "updated_at", None)
            else created
        )

        # Use canonical STIX ID if present, else mint from entity UUID
        stix_id = getattr(entity, "stix_id", None) or f"{stix_type}--{entity.id}"

        obj: dict = {
            "type": stix_type,
            "id": stix_id,
            "spec_version": "2.1",
            "created": created,
            "modified": modified,
            "name": name,
        }
        if getattr(entity, "description", None):
            obj["description"] = entity.description

        kind_val = entity.kind.value if hasattr(entity.kind, "value") else str(entity.kind)

        if stix_type == "indicator":
            pattern = STIX_INDICATOR_PATTERNS.get(kind_val, "[x-value:value = '{value}']")
            obj["pattern"] = pattern.format(value=name)
            obj["pattern_type"] = "stix"
            obj["valid_from"] = created
            obj["indicator_types"] = ["malicious-activity"]

        if stix_type == "threat-actor":
            obj["threat_actor_types"] = ["unknown"]

        if stix_type == "identity":
            obj["identity_class"] = "organization"

        if stix_type == "malware":
            obj["malware_types"] = ["unknown"]
            obj["is_family"] = False

        # Include MITRE ATT&CK ID as external reference
        mitre_id = getattr(entity, "mitre_attack_id", None)
        if mitre_id:
            obj["external_references"] = [
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre_id,
                    "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
                }
            ]

        objects.append(obj)

    # ---------- Claims → STIX Note objects ----------
    for claim in claims:
        claim_id = getattr(claim, "id", uuid.uuid4())
        created = (
            claim.created_at.isoformat()
            if getattr(claim, "created_at", None)
            else datetime.now(timezone.utc).isoformat()
        )
        note_obj = {
            "type": "note",
            "id": f"note--{claim_id}",
            "spec_version": "2.1",
            "created": created,
            "modified": created,
            "content": getattr(claim, "statement", ""),
            "abstract": getattr(claim, "claim_type", "general"),
            "confidence": int(getattr(claim, "confidence", 1.0) * 100),
        }
        objects.append(note_obj)

    # ---------- Relationships → STIX relationship SROs ----------
    for rel in (relationships or []):
        rel_id = getattr(rel, "id", uuid.uuid4())
        stix_rel_id = getattr(rel, "stix_id", None) or f"relationship--{rel_id}"
        source_entity_id = getattr(rel, "source_id", None)
        target_entity_id = getattr(rel, "target_id", None)
        created = (
            rel.created_at.isoformat()
            if getattr(rel, "created_at", None)
            else datetime.now(timezone.utc).isoformat()
        )
        # Resolve STIX IDs for source/target from the entity list
        src_stix_id = next(
            (f"{ENTITY_KIND_TO_STIX_TYPE.get(e.kind, 'x-custom-object')}--{e.id}"
             for e in entities if str(e.id) == str(source_entity_id)),
            f"x-custom-object--{source_entity_id}",
        )
        tgt_stix_id = next(
            (f"{ENTITY_KIND_TO_STIX_TYPE.get(e.kind, 'x-custom-object')}--{e.id}"
             for e in entities if str(e.id) == str(target_entity_id)),
            f"x-custom-object--{target_entity_id}",
        )
        objects.append({
            "type": "relationship",
            "id": stix_rel_id,
            "spec_version": "2.1",
            "created": created,
            "modified": created,
            "relationship_type": getattr(rel, "relationship_type", "related-to"),
            "source_ref": src_stix_id,
            "target_ref": tgt_stix_id,
            "description": getattr(rel, "description", ""),
            "confidence": int(getattr(rel, "confidence", 1.0) * 100),
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }
