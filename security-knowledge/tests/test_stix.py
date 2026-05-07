import pytest
import uuid
from unittest.mock import MagicMock
from app.stix.builder import build_stix_bundle
from app.models.entities import EntityKind


def make_entity(kind: EntityKind, name: str):
    from datetime import datetime, timezone
    e = MagicMock()
    e.id = uuid.uuid4()
    e.name = name
    e.canonical_name = name
    e.kind = kind
    e.description = None
    e.created_at = datetime.now(timezone.utc)
    e.updated_at = datetime.now(timezone.utc)
    return e


def test_build_stix_bundle_empty():
    bundle = build_stix_bundle([], [])
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert bundle["objects"] == []


def test_build_stix_bundle_cve():
    entity = make_entity(EntityKind.cve, "CVE-2024-1234")
    bundle = build_stix_bundle([entity], [])
    assert len(bundle["objects"]) == 1
    obj = bundle["objects"][0]
    assert obj["type"] == "vulnerability"
    assert obj["name"] == "CVE-2024-1234"


def test_build_stix_bundle_actor():
    entity = make_entity(EntityKind.actor, "APT28")
    bundle = build_stix_bundle([entity], [])
    obj = bundle["objects"][0]
    assert obj["type"] == "threat-actor"


def test_build_stix_bundle_indicator():
    entity = make_entity(EntityKind.ip_address, "192.168.1.1")
    bundle = build_stix_bundle([entity], [])
    obj = bundle["objects"][0]
    assert obj["type"] == "indicator"
    assert "pattern" in obj
