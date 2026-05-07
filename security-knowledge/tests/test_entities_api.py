import pytest
from unittest.mock import AsyncMock, MagicMock
import uuid


@pytest.mark.asyncio
async def test_list_entities_empty(client, mock_db, tenant_id):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/entities/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_entity_validates_kind(client, mock_db):
    resp = await client.post("/api/v1/entities/", json={"name": "test", "kind": "not_a_valid_kind"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_entity_validates_missing_kind(client, mock_db):
    resp = await client.post("/api/v1/entities/", json={"name": "test"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_entity_not_found(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get(f"/api/v1/entities/{uuid.uuid4()}")
    assert resp.status_code == 404
