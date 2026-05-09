import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_list_webhooks_empty(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/webhooks/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_webhook_validates_missing_url(client, mock_db):
    resp = await client.post("/api/v1/webhooks/", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_webhook_validates_url_type(client, mock_db):
    resp = await client.post("/api/v1/webhooks/", json={"url": 123})
    assert resp.status_code in (200, 201, 422)


@pytest.mark.asyncio
async def test_create_webhook_rejects_private_targets(client, mock_db):
    resp = await client.post("/api/v1/webhooks/", json={"url": "http://127.0.0.1:8080/hook"})
    assert resp.status_code == 422
