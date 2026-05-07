"""Tests for STIX 2.1 builder and export endpoint."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entity(kind="malware", name="EvilBot", with_mitre=False):
    e = MagicMock()
    e.id = uuid.uuid4()
    e.kind = kind
    e.canonical_name = name
    e.name = name
    e.description = "A nasty piece of malware"
    e.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    e.updated_at = datetime(2024, 6, 1, tzinfo=timezone.utc)
    e.stix_id = None
    e.mitre_attack_id = "T1059.001" if with_mitre else None
    return e


def _make_claim():
    c = MagicMock()
    c.id = uuid.uuid4()
    c.statement = "This malware uses PowerShell for execution"
    c.claim_type = "technique"
    c.confidence = 0.9
    c.created_at = datetime(2024, 3, 1, tzinfo=timezone.utc)
    return c


def _make_relationship(source_id, target_id):
    r = MagicMock()
    r.id = uuid.uuid4()
    r.stix_id = None
    r.source_id = source_id
    r.target_id = target_id
    r.relationship_type = "uses"
    r.confidence = 0.85
    r.description = "Uses for execution"
    r.created_at = datetime(2024, 3, 1, tzinfo=timezone.utc)
    return r


# ---------------------------------------------------------------------------
# Builder unit tests
# ---------------------------------------------------------------------------

class TestBuildStixBundle:
    def test_empty_bundle(self):
        from app.stix.builder import build_stix_bundle
        bundle = build_stix_bundle([], [], [])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert bundle["objects"] == []
        assert bundle["id"].startswith("bundle--")

    def test_malware_entity(self):
        from app.stix.builder import build_stix_bundle
        entity = _make_entity("malware", "EvilBot")
        bundle = build_stix_bundle([entity], [], [])
        obj = bundle["objects"][0]
        assert obj["type"] == "malware"
        assert obj["name"] == "EvilBot"
        assert obj["spec_version"] == "2.1"
        assert obj["is_family"] is False

    def test_indicator_entity_has_pattern(self):
        from app.stix.builder import build_stix_bundle
        entity = _make_entity("ip_address", "1.2.3.4")
        bundle = build_stix_bundle([entity], [], [])
        obj = bundle["objects"][0]
        assert obj["type"] == "indicator"
        assert "pattern" in obj
        assert "1.2.3.4" in obj["pattern"]
        assert obj["pattern_type"] == "stix"
        assert "valid_from" in obj

    def test_threat_actor_entity(self):
        from app.stix.builder import build_stix_bundle
        entity = _make_entity("actor", "APT99")
        bundle = build_stix_bundle([entity], [], [])
        obj = bundle["objects"][0]
        assert obj["type"] == "threat-actor"
        assert "threat_actor_types" in obj

    def test_mitre_external_reference(self):
        from app.stix.builder import build_stix_bundle
        entity = _make_entity("attack_pattern", "PowerShell", with_mitre=True)
        bundle = build_stix_bundle([entity], [], [])
        obj = bundle["objects"][0]
        assert "external_references" in obj
        assert obj["external_references"][0]["source_name"] == "mitre-attack"
        assert obj["external_references"][0]["external_id"] == "T1059.001"

    def test_claim_becomes_note(self):
        from app.stix.builder import build_stix_bundle
        claim = _make_claim()
        bundle = build_stix_bundle([], [claim], [])
        obj = bundle["objects"][0]
        assert obj["type"] == "note"
        assert obj["content"] == claim.statement
        assert obj["id"].startswith("note--")

    def test_relationship_sro(self):
        from app.stix.builder import build_stix_bundle
        e1 = _make_entity("actor", "APT99")
        e2 = _make_entity("malware", "EvilBot")
        rel = _make_relationship(e1.id, e2.id)
        bundle = build_stix_bundle([e1, e2], [], [rel])
        rel_objs = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rel_objs) == 1
        assert rel_objs[0]["relationship_type"] == "uses"
        assert "threat-actor" in rel_objs[0]["source_ref"]

    def test_stix_id_preserved(self):
        from app.stix.builder import build_stix_bundle
        entity = _make_entity("malware", "KeepID")
        entity.stix_id = "malware--12345678-1234-5678-1234-567812345678"
        bundle = build_stix_bundle([entity], [], [])
        assert bundle["objects"][0]["id"] == entity.stix_id

    def test_bundle_id_unique(self):
        from app.stix.builder import build_stix_bundle
        b1 = build_stix_bundle([], [], [])
        b2 = build_stix_bundle([], [], [])
        assert b1["id"] != b2["id"]


# ---------------------------------------------------------------------------
# Export endpoint tests
# ---------------------------------------------------------------------------

class TestExportStixEndpoint:
    @pytest.mark.asyncio
    async def test_export_returns_stix_content_type(self):
        """Export endpoint returns application/stix+json content type."""
        from app.routers.export import router
        from fastapi import FastAPI
        from httpx import AsyncClient, ASGITransport

        from app.auth.dependencies import require_read
        from app.database import get_db

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))

        mock_auth = MagicMock()
        mock_auth.tenant_id = uuid.uuid4()

        test_app = FastAPI()
        test_app.include_router(router)
        test_app.dependency_overrides[get_db] = lambda: mock_db
        test_app.dependency_overrides[require_read] = lambda: mock_auth

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            resp = await client.get("/export/stix")

        assert resp.status_code == 200
        assert "stix+json" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_export_valid_bundle_structure(self):
        """Export endpoint returns a valid STIX 2.1 bundle."""
        import json
        from app.routers.export import router
        from fastapi import FastAPI
        from httpx import AsyncClient, ASGITransport
        from app.auth.dependencies import require_read
        from app.database import get_db

        mock_scalars = MagicMock()
        mock_scalars.all = MagicMock(return_value=[])
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_scalars)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        mock_auth = MagicMock()
        mock_auth.tenant_id = uuid.uuid4()

        test_app = FastAPI()
        test_app.include_router(router)
        test_app.dependency_overrides[get_db] = lambda: mock_db
        test_app.dependency_overrides[require_read] = lambda: mock_auth

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            resp = await client.get("/export/stix")

        assert resp.status_code == 200
        bundle = json.loads(resp.content)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert isinstance(bundle["objects"], list)
        assert "X-STIX-Bundle-ID" in resp.headers
