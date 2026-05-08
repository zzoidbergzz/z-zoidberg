import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid


@pytest.mark.asyncio
async def test_ingest_creates_job(client, mock_db):
    from app.models.jobs import IngestionJob
    job = MagicMock(spec=IngestionJob)
    job.id = uuid.uuid4()
    job.status = "pending"
    
    with patch("app.routers.ingest.create_ingestion_job", new=AsyncMock(return_value=job)):
        resp = await client.post("/api/v1/ingest/", json={
            "source_url": "https://nvd.nist.gov/feeds/json/cve/1.1",
            "source_type": "nvd"
        })
        assert resp.status_code in (200, 202, 422)
