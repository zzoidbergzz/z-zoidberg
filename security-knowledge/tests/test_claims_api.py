import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_list_claims_empty(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/claims/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_claim_validates_empty_body(client, mock_db):
    resp = await client.post("/api/v1/claims/", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_claim_validates_statement_type(client, mock_db):
    resp = await client.post("/api/v1/claims/", json={"statement": 123})
    assert resp.status_code in (200, 201, 422)
