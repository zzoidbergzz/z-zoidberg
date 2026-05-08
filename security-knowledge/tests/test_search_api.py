import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_search_requires_query(client):
    resp = await client.get("/api/v1/search/")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_returns_results(client, mock_db):
    with patch("app.routers.search.full_text_search", new=AsyncMock(return_value=[
        {"kind": "entity", "id": "abc", "name": "CVE-2024-1234", "score": 1.0}
    ])):
        resp = await client.get("/api/v1/search/?q=CVE-2024")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "CVE-2024-1234"
