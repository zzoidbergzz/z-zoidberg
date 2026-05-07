"""Tests for MITRE ATT&CK integration (service, router, MCP, enrichment)."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport


# ---------------------------------------------------------------------------
# Shared mock fixture
# ---------------------------------------------------------------------------

def _make_stix_obj(attack_id: str, name: str, obj_type: str = "attack-pattern", description: str = "Test description") -> MagicMock:
    obj = MagicMock()
    obj.id = f"{obj_type}--aaaaaaaa-bbbb-cccc-dddd-{attack_id.replace('.', '').lower():012s}"
    obj.type = obj_type
    obj.name = name
    obj.description = description

    ref = MagicMock()
    ref.source_name = "mitre-attack"
    ref.external_id = attack_id
    ref.get = lambda key, default=None: {"source_name": "mitre-attack", "external_id": attack_id}.get(key, default)
    obj.external_references = [ref]

    kc = MagicMock()
    kc.phase_name = "execution"
    kc.get = lambda key, default=None: {"phase_name": "execution"}.get(key, default)
    obj.kill_chain_phases = [kc]

    obj.x_mitre_platforms = ["Linux", "Windows"]
    obj.x_mitre_is_subtechnique = False
    obj.x_mitre_deprecated = False
    obj.revoked = False
    obj.aliases = None
    obj.created = "2024-01-01T00:00:00Z"
    obj.modified = "2024-06-01T00:00:00Z"
    return obj


@pytest.fixture
def mock_attack_data():
    """Mock MitreAttackData with predictable responses."""
    mock = MagicMock()

    t1059 = _make_stix_obj("T1059", "Command and Scripting Interpreter")
    g0016 = _make_stix_obj("G0016", "APT29", obj_type="intrusion-set")

    mock.get_object_by_attack_id.return_value = t1059
    mock.get_object_by_stix_id.return_value = t1059
    mock.get_objects_by_name.return_value = [t1059]
    mock.get_objects_by_content.return_value = [t1059]
    mock.get_techniques.return_value = [t1059]
    mock.get_subtechniques.return_value = []
    mock.get_groups.return_value = [g0016]
    mock.get_software.return_value = []
    mock.get_mitigations.return_value = []
    mock.get_campaigns.return_value = []
    mock.get_tactics.return_value = []
    mock.get_techniques_used_by_group.return_value = [{"object": t1059, "relationships": []}]
    mock.get_software_used_by_group.return_value = []
    mock.get_campaigns_attributed_to_group.return_value = []
    mock.get_groups_using_technique.return_value = [{"object": g0016, "relationships": []}]
    mock.get_mitigations_mitigating_technique.return_value = []
    mock.get_datacomponents_detecting_technique.return_value = []
    mock.get_procedure_examples_by_technique.return_value = []
    mock.get_campaigns_using_technique.return_value = []
    mock.get_techniques_used_by_software.return_value = []
    mock.get_techniques_used_by_campaign.return_value = []
    mock.get_techniques_mitigated_by_mitigation.return_value = []
    mock.get_subtechniques_of_technique.return_value = []
    mock.get_parent_technique_of_subtechnique.return_value = None
    mock.get_techniques_by_tactic.return_value = [t1059]
    mock.get_techniques_by_platform.return_value = [t1059]
    mock.get_objects_created_after.return_value = []
    mock.get_objects_modified_after.return_value = []
    mock.get_groups_by_alias.return_value = []
    mock.get_software_by_alias.return_value = []
    return mock


@pytest.fixture
async def mitre_client(mock_db, tenant_id, api_key_value, mock_attack_data):
    """HTTP client with MITRE data mocked."""
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import AuthContext, Scope, require_scope, get_auth
    from app.services import mitre_attack

    auth_ctx = AuthContext(tenant_id=tenant_id, scopes=set(Scope), user_id=None, auth_type="api_key")

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth_ctx
    app.dependency_overrides[require_scope(Scope.read)] = lambda: auth_ctx
    app.dependency_overrides[require_scope(Scope.admin)] = lambda: auth_ctx

    mitre_attack._instances["enterprise"] = mock_attack_data

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
    mitre_attack._instances.clear()


# ---------------------------------------------------------------------------
# /mitre/status
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mitre_status(mitre_client):
    resp = await mitre_client.get("/api/v1/mitre/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "loaded_domains" in data
    assert "enterprise" in data["loaded_domains"]
    assert "data_dir" in data


# ---------------------------------------------------------------------------
# /mitre/techniques
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mitre_techniques_list(mitre_client):
    resp = await mitre_client.get("/api/v1/mitre/techniques?domain=enterprise")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["attack_id"] == "T1059"
    assert data[0]["name"] == "Command and Scripting Interpreter"


@pytest.mark.asyncio
async def test_mitre_techniques_empty_when_not_loaded(mock_db, tenant_id, api_key_value):
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import AuthContext, Scope, get_auth
    from app.services import mitre_attack

    auth_ctx = AuthContext(tenant_id=tenant_id, scopes=set(Scope))
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth_ctx

    # Remove enterprise from cache and patch load to raise
    mitre_attack._instances.pop("enterprise", None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        with patch("app.services.mitre_attack.get_attack_data", side_effect=FileNotFoundError("no such file")):
            resp = await ac.get("/api/v1/mitre/techniques?domain=enterprise")
            # Service catches errors and returns empty list — status 200 with []
            assert resp.status_code == 200
            assert resp.json() == []

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# /mitre/techniques/{attack_id}
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mitre_technique_by_id(mitre_client):
    resp = await mitre_client.get("/api/v1/mitre/techniques/T1059")
    assert resp.status_code == 200
    data = resp.json()
    assert data["attack_id"] == "T1059"
    assert data["name"] == "Command and Scripting Interpreter"
    assert "stix_id" in data


@pytest.mark.asyncio
async def test_mitre_technique_not_found(mitre_client, mock_attack_data):
    mock_attack_data.get_object_by_attack_id.return_value = None
    resp = await mitre_client.get("/api/v1/mitre/techniques/T9999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /mitre/groups
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mitre_groups_list(mitre_client):
    resp = await mitre_client.get("/api/v1/mitre/groups")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert any(g["attack_id"] == "G0016" for g in data)


# ---------------------------------------------------------------------------
# /mitre/search
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mitre_search_by_name(mitre_client):
    resp = await mitre_client.get("/api/v1/mitre/search?q=Command")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


# ---------------------------------------------------------------------------
# MCP tool dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mcp_tools_list(mitre_client):
    resp = await mitre_client.get("/api/v1/mcp/tools")
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert "enrich_entity" in data["tools"]
    assert "get_object_by_attack_id" in data["tools"]
    assert "get_techniques_used_by_group" in data["tools"]


@pytest.mark.asyncio
async def test_mcp_call_get_object_by_attack_id(mitre_client):
    resp = await mitre_client.post(
        "/api/v1/mcp/call",
        json={"tool": "get_object_by_attack_id", "args": {"attack_id": "T1059"}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "result" in data
    result = data["result"]
    assert result is not None
    assert result["attack_id"] == "T1059"


@pytest.mark.asyncio
async def test_mcp_call_missing_required_arg(mitre_client):
    resp = await mitre_client.post(
        "/api/v1/mcp/call",
        json={"tool": "get_object_by_attack_id", "args": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mcp_call_unknown_tool(mitre_client):
    resp = await mitre_client.post(
        "/api/v1/mcp/call",
        json={"tool": "nonexistent_tool", "args": {}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data


# ---------------------------------------------------------------------------
# Enrichment provider
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mitre_enrichment_provider_by_attack_id(mock_attack_data):
    from app.services import mitre_attack
    from app.enrichment.providers.mitre_attack import MitreAttackProvider

    mitre_attack._instances["enterprise"] = mock_attack_data

    provider = MitreAttackProvider()
    result = await provider.enrich("attack_pattern", "T1059")
    assert result["attack_id"] == "T1059"
    assert result["name"] == "Command and Scripting Interpreter"
    assert "tactics" in result
    assert "platforms" in result

    mitre_attack._instances.clear()


@pytest.mark.asyncio
async def test_mitre_enrichment_provider_by_name(mock_attack_data):
    from app.services import mitre_attack
    from app.enrichment.providers.mitre_attack import MitreAttackProvider

    mitre_attack._instances["enterprise"] = mock_attack_data

    provider = MitreAttackProvider()
    result = await provider.enrich("attack_pattern", "Command and Scripting Interpreter")
    assert result["name"] == "Command and Scripting Interpreter"

    mitre_attack._instances.clear()


@pytest.mark.asyncio
async def test_mitre_enrichment_provider_not_found(mock_attack_data):
    from app.services import mitre_attack
    from app.enrichment.providers.mitre_attack import MitreAttackProvider

    mock_attack_data.get_objects_by_name.return_value = []
    mitre_attack._instances["enterprise"] = mock_attack_data

    provider = MitreAttackProvider()
    result = await provider.enrich("attack_pattern", "NonExistentTechnique")
    assert result == {}

    mitre_attack._instances.clear()


# ---------------------------------------------------------------------------
# Service-level unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_service_get_object_by_attack_id(mock_attack_data):
    from app.services import mitre_attack

    mitre_attack._instances["enterprise"] = mock_attack_data
    result = await mitre_attack.get_object_by_attack_id("T1059")
    assert result is not None
    assert result["attack_id"] == "T1059"
    mitre_attack._instances.clear()


@pytest.mark.asyncio
async def test_service_get_all_techniques(mock_attack_data):
    from app.services import mitre_attack

    mitre_attack._instances["enterprise"] = mock_attack_data
    results = await mitre_attack.get_all_techniques()
    assert isinstance(results, list)
    assert len(results) == 1
    mitre_attack._instances.clear()


@pytest.mark.asyncio
async def test_service_handles_exception_gracefully(mock_attack_data):
    from app.services import mitre_attack

    mock_attack_data.get_object_by_attack_id.side_effect = Exception("STIX error")
    mitre_attack._instances["enterprise"] = mock_attack_data

    result = await mitre_attack.get_object_by_attack_id("T9999")
    assert result is None
    mitre_attack._instances.clear()
