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
    ])), patch("app.routers.search.searxng_search", new=AsyncMock(return_value=[])):
        resp = await client.get("/api/v1/search/?q=CVE-2024")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_search_falls_back_to_searxng_when_db_sparse(client, mock_db):
    with patch("app.routers.search.full_text_search", new=AsyncMock(return_value=[])), patch(
        "app.routers.search.searxng_search",
        new=AsyncMock(return_value=[{"title": "Web CVE", "url": "https://example.com/cve", "content": "details", "score": 0.9}]),
    ):
        resp = await client.get("/api/v1/search/?q=CVE-2024")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["kind"] == "web_result"
        assert data[0]["detail_url"] == "https://example.com/cve"


@pytest.mark.asyncio
async def test_search_web_only_uses_searxng(client, mock_db):
    with patch("app.routers.search.full_text_search", new=AsyncMock(return_value=[])), patch(
        "app.routers.search.searxng_search",
        new=AsyncMock(return_value=[{"title": "Bristol", "url": "https://en.wikipedia.org/wiki/Bristol", "content": "UK city", "score": 0.8}]),
    ):
        resp = await client.get("/api/v1/search/?q=bristol&web_only=true")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["kind"] == "web_result"
        assert data[0]["name"] == "Bristol"
