import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_list_audit_empty(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/audit/")
    assert resp.status_code == 200
    assert resp.json() == []
