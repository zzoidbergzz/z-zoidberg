"""Tests for the enrich_entity MCP tool."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_enrich_entity_tool_envelope_and_error_capture():
    """Two providers: alpha returns data, beta raises — verify envelope shape and error capture."""
    from app.mcp.tools.enrich_entity import EnrichEntityInput, enrich_entity_tool

    inp = EnrichEntityInput(
        entity_kind="cve",
        entity_value="CVE-2024-1234",
        tenant_id="tenant-abc",
    )
    mock_db = AsyncMock()

    async def fake_enrich(provider_name: str, entity_kind: str, entity_value: str) -> dict:
        if provider_name == "alpha":
            return {"cvss": 9.8, "vendor": "example"}
        raise RuntimeError("beta connection refused")

    with patch("app.mcp.tools.enrich_entity.list_providers", return_value=["alpha", "beta"]):
        with patch("app.mcp.tools.enrich_entity.EnrichmentService") as MockService:
            instance = MagicMock()
            instance.enrich = AsyncMock(side_effect=fake_enrich)
            MockService.return_value = instance

            out = await enrich_entity_tool(inp, mock_db)

    # Envelope shape
    assert out.entity_kind == "cve"
    assert out.entity_value == "CVE-2024-1234"
    assert out.count == 2
    assert len(out.results) == 2

    # alpha: successful result
    alpha = next(r for r in out.results if r.provider == "alpha")
    assert alpha.ok is True
    assert alpha.data == {"cvss": 9.8, "vendor": "example"}
    assert alpha.error is None

    # beta: error captured, not propagated
    beta = next(r for r in out.results if r.provider == "beta")
    assert beta.ok is False
    assert beta.data == {}
    assert "beta connection refused" in (beta.error or "")


@pytest.mark.asyncio
async def test_enrich_entity_tool_provider_filter():
    """When providers list is given, only those providers are called."""
    from app.mcp.tools.enrich_entity import EnrichEntityInput, enrich_entity_tool

    inp = EnrichEntityInput(
        entity_kind="ip_address",
        entity_value="1.2.3.4",
        providers=["shodan"],
        tenant_id="tenant-abc",
    )
    mock_db = AsyncMock()

    with patch("app.mcp.tools.enrich_entity.list_providers", return_value=["shodan", "virustotal"]):
        with patch("app.mcp.tools.enrich_entity.EnrichmentService") as MockService:
            instance = MagicMock()
            instance.enrich = AsyncMock(return_value={"ports": [80, 443]})
            MockService.return_value = instance

            out = await enrich_entity_tool(inp, mock_db)

    assert out.count == 1
    assert out.results[0].provider == "shodan"
    assert out.results[0].ok is True
    assert out.results[0].data == {"ports": [80, 443]}


@pytest.mark.asyncio
async def test_enrich_entity_tool_no_providers_registered():
    """When no providers are registered, results list is empty."""
    from app.mcp.tools.enrich_entity import EnrichEntityInput, enrich_entity_tool

    inp = EnrichEntityInput(
        entity_kind="domain",
        entity_value="evil.example.com",
        tenant_id="tenant-abc",
    )
    mock_db = AsyncMock()

    with patch("app.mcp.tools.enrich_entity.list_providers", return_value=[]):
        with patch("app.mcp.tools.enrich_entity.EnrichmentService"):
            out = await enrich_entity_tool(inp, mock_db)

    assert out.entity_kind == "domain"
    assert out.entity_value == "evil.example.com"
    assert out.count == 0
    assert out.results == []
