"""MITRE ATT&CK enrichment provider."""
from __future__ import annotations

import re
from typing import Any

from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.services import mitre_attack


@register
class MitreAttackProvider(BaseEnrichmentProvider):
    name = "mitre_attack"
    kind = "attack_pattern"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        """
        entity_kind: "attack_pattern", "technique", "group", "software", "campaign"
        entity_value: ATT&CK ID (T1059, G0016, S0001, C0001) or STIX ID or name
        """
        obj: dict | None = None

        if re.match(r"^[TGSC]\d{4}(\.\d{3})?$", entity_value):
            obj = await mitre_attack.get_object_by_attack_id(entity_value)
        elif re.match(r"^(attack-pattern|intrusion-set|malware|tool|campaign|course-of-action)--", entity_value):
            obj = await mitre_attack.get_object_by_stix_id(entity_value)
        else:
            results = await mitre_attack.get_objects_by_name(entity_value)
            obj = results[0] if results else None

        if obj is None:
            return {}

        return {
            "attack_id": obj.get("attack_id"),
            "name": obj.get("name"),
            "description": obj.get("description", ""),
            "tactics": obj.get("tactics", []),
            "platforms": obj.get("platforms", []),
            "type": obj.get("type"),
            "stix_id": obj.get("stix_id"),
            "references": [],
            "revoked": obj.get("revoked", False),
            "is_subtechnique": obj.get("is_subtechnique", False),
        }
