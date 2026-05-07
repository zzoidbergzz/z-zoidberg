import uuid
from datetime import datetime, timezone
from app.stix.mapping import ENTITY_KIND_TO_STIX_TYPE, STIX_INDICATOR_PATTERNS


def _entity_name(entity) -> str:
    return getattr(entity, "name", None) or getattr(entity, "canonical_name", "?")


def build_stix_bundle(entities: list, claims: list) -> dict:
    objects = []
    for entity in entities:
        stix_type = ENTITY_KIND_TO_STIX_TYPE.get(entity.kind, "x-custom-object")
        name = _entity_name(entity)
        obj = {
            "type": stix_type,
            "id": f"{stix_type}--{entity.id}",
            "spec_version": "2.1",
            "created": entity.created_at.isoformat() if entity.created_at else datetime.now(timezone.utc).isoformat(),
            "modified": entity.updated_at.isoformat() if entity.updated_at else datetime.now(timezone.utc).isoformat(),
            "name": name,
        }
        if entity.description:
            obj["description"] = entity.description
        kind_val = entity.kind.value if hasattr(entity.kind, "value") else str(entity.kind)
        if stix_type == "indicator":
            pattern = STIX_INDICATOR_PATTERNS.get(kind_val, "[x-value:value = '{value}']")
            obj["pattern"] = pattern.format(value=name)
            obj["pattern_type"] = "stix"
            obj["valid_from"] = obj["created"]
        objects.append(obj)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }
