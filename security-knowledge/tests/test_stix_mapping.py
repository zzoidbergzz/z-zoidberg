import pytest
from app.stix.mapping import ENTITY_KIND_TO_STIX_TYPE, STIX_INDICATOR_PATTERNS
from app.models.entities import EntityKind


def test_cve_maps_to_vulnerability():
    assert ENTITY_KIND_TO_STIX_TYPE[EntityKind.cve] == "vulnerability"


def test_actor_maps_to_threat_actor():
    assert ENTITY_KIND_TO_STIX_TYPE[EntityKind.actor] == "threat-actor"


def test_malware_maps_to_malware():
    assert ENTITY_KIND_TO_STIX_TYPE[EntityKind.malware] == "malware"


def test_ip_maps_to_indicator():
    assert ENTITY_KIND_TO_STIX_TYPE[EntityKind.ip_address] == "indicator"


def test_technique_maps_to_attack_pattern():
    assert ENTITY_KIND_TO_STIX_TYPE[EntityKind.attack_pattern] == "attack-pattern"


def test_indicator_patterns_ip():
    pattern = STIX_INDICATOR_PATTERNS["ip_address"].format(value="1.2.3.4")
    assert "1.2.3.4" in pattern
    assert "ipv4-addr" in pattern
