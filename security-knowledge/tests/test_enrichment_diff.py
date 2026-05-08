"""Tests for enrichment diff computation and force-refresh endpoint."""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for compute_diff
# ──────────────────────────────────────────────────────────────────────────────

def test_compute_diff_added_keys():
    from app.services.enrichment_diff import compute_diff
    old = {"a": 1}
    new = {"a": 1, "b": 2}
    result = compute_diff(old, new)
    assert result["added"] == {"b": 2}
    assert result["removed"] == {}
    assert result["changed"] == {}


def test_compute_diff_removed_keys():
    from app.services.enrichment_diff import compute_diff
    old = {"a": 1, "b": 2}
    new = {"a": 1}
    result = compute_diff(old, new)
    assert result["removed"] == {"b": 2}
    assert result["added"] == {}
    assert result["changed"] == {}


def test_compute_diff_changed_value():
    from app.services.enrichment_diff import compute_diff
    old = {"score": 10}
    new = {"score": 20}
    result = compute_diff(old, new)
    assert result["changed"] == {"score": [10, 20]}


def test_compute_diff_no_changes():
    from app.services.enrichment_diff import compute_diff
    data = {"a": 1, "b": "x"}
    result = compute_diff(data, data.copy())
    assert result == {"added": {}, "removed": {}, "changed": {}}


def test_compute_diff_empty_dicts():
    from app.services.enrichment_diff import compute_diff
    result = compute_diff({}, {})
    assert result == {"added": {}, "removed": {}, "changed": {}}


# ──────────────────────────────────────────────────────────────────────────────
# Integration-style test for force refresh endpoint (mocked DB + provider)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_force_refresh_endpoint(mock_db, tenant_id):
    """POST /enrich/{kind}/{value}/refresh returns data + diff."""
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope
    from unittest.mock import patch, AsyncMock as AM
    from httpx import AsyncClient, ASGITransport

    auth_ctx = AuthContext(
        tenant_id=tenant_id,
        scopes={Scope.enrichment},
        user_id=str(uuid.uuid4()),
        auth_type="api_key",
    )
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth_ctx

    # Mock the force_refresh_enrichment function
    from app.models.enrichment import EnrichmentDiff as DiffModel
    mock_diff = MagicMock(spec=DiffModel)
    mock_diff.diff_summary = {"added": {"x": 1}, "removed": {}, "changed": {}}
    mock_diff.has_changes = True

    with patch(
        "app.services.enrichment_diff.force_refresh_enrichment",
        new=AsyncMock(return_value=({"score": 5}, mock_diff)),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(
                "/api/v1/enrich/ip/1.2.3.4/refresh?provider=virustotal"
            )

    app.dependency_overrides.clear()
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_kind"] == "ip"
    assert data["entity_value"] == "1.2.3.4"
    assert data["has_changes"] is True


@pytest.mark.asyncio
async def test_force_refresh_missing_provider(mock_db, tenant_id):
    """POST /enrich/{kind}/{value}/refresh returns 422 if provider param missing."""
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope
    from httpx import AsyncClient, ASGITransport

    auth_ctx = AuthContext(
        tenant_id=tenant_id,
        scopes={Scope.enrichment},
        user_id=str(uuid.uuid4()),
        auth_type="api_key",
    )
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth_ctx

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/enrich/ip/1.2.3.4/refresh")

    app.dependency_overrides.clear()
    assert resp.status_code == 422
