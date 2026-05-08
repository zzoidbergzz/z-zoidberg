import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_list_sources_empty(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/sources/")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
