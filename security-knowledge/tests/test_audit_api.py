import pytest
from unittest.mock import AsyncMock, MagicMock
import uuid
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_list_audit_empty(client, mock_db):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)
    resp = await client.get("/api/v1/audit/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_audit_populated(client, mock_db, tenant_id):
    class AuditRow:
        def __init__(self, actor, resource_type, resource_id, details):
            self.id = uuid.uuid4()
            self.action = "ingest_complete"
            self.actor = actor
            self.resource_type = resource_type
            self.resource_id = resource_id
            self.details = details
            self.created_at = datetime.now(timezone.utc)
            self.tenant_id = uuid.UUID(tenant_id)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [
        AuditRow("worker", "parsed_document", str(uuid.uuid4()), {"source_kind": "internal automation"}),
        AuditRow("alice@example.com", "lookup", str(uuid.uuid4()), {"source_kind": "external users", "entity_id": str(uuid.uuid4())}),
    ]
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await client.get("/api/v1/audit/")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload[0]["actor"] == "worker"
    assert payload[0]["source_kind"] == "internal automation"
    assert payload[1]["source_kind"] == "external users"
    assert payload[1]["activity_url"].startswith("/lookup/entity/")


@pytest.mark.asyncio
async def test_list_audit_source_filter(client, mock_db, tenant_id):
    class AuditRow:
        def __init__(self, actor, resource_type, resource_id, details):
            self.id = uuid.uuid4()
            self.action = "fingerprint_collected"
            self.actor = actor
            self.resource_type = resource_type
            self.resource_id = resource_id
            self.details = details
            self.created_at = datetime.now(timezone.utc)
            self.tenant_id = uuid.UUID(tenant_id)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [
        AuditRow("worker", "parsed_document", str(uuid.uuid4()), {"source_kind": "internal automation"}),
        AuditRow("alice@example.com", "fingerprint", str(uuid.uuid4()), {"source_kind": "external users"}),
    ]
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await client.get("/api/v1/audit/?source=external")
    assert resp.status_code == 200
    payload = resp.json()
    assert len(payload) == 1
    assert payload[0]["source_kind"] == "external users"
    assert payload[0]["activity_url"] == "/fingerprint"


@pytest.mark.asyncio
async def test_worker_ingest_classifies_internal(client, mock_db, tenant_id):
    class AuditRow:
        def __init__(self):
            self.id = uuid.uuid4()
            self.action = "ingest_complete"
            self.actor = "worker-ingest"
            self.resource_type = "parsed_document"
            self.resource_id = str(uuid.uuid4())
            self.details = {}
            self.created_at = datetime.now(timezone.utc)
            self.tenant_id = uuid.UUID(tenant_id)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [AuditRow()]
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await client.get("/api/v1/audit/?source=internal")
    assert resp.status_code == 200
    payload = resp.json()
    assert len(payload) == 1
    assert payload[0]["source_kind"] == "internal automation"
