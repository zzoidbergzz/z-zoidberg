from __future__ import annotations

from pathlib import Path
import hashlib
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient, ASGITransport


def test_lookup_ioc_registered_write_scope():
    import app.mcp.tools.lookup_ioc  # noqa: F401
    from app.mcp.registry import get_tool

    tool = get_tool("lookup_ioc")
    assert tool is not None
    assert tool.scope == "write"


def test_mcp_build_auth_uses_supplied_scopes():
    from app.auth.dependencies import Scope
    from app.mcp.server import _build_auth

    auth = _build_auth(scopes={Scope.read})
    assert Scope.read in auth.scopes
    assert Scope.write not in auth.scopes


def test_mcp_sse_scope_parsing():
    from app.auth.dependencies import Scope
    from app.mcp.server import _parse_scopes

    scopes = _parse_scopes("read, unknown")
    assert scopes == {Scope.read}


def test_malware_locate_standalone_blocks_traversal(monkeypatch, tmp_path):
    import importlib
    from app.routers import malware

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    importlib.reload(malware)
    repo_root = tmp_path / "z-zoidberg" / "repos" / "repo1"
    repo_root.mkdir(parents=True)
    (repo_root / "safe.bin").write_bytes(b"safe")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")

    assert malware._locate_standalone("", "../outside.txt", "repo1") is None
    assert malware._locate_standalone("", "safe.bin", "repo1") == b"safe"


def test_malware_locate_zip_blocks_traversal(monkeypatch, tmp_path):
    import importlib
    from app.routers import malware

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    importlib.reload(malware)
    repo_root = tmp_path / "z-zoidberg" / "repos" / "repo1"
    repo_root.mkdir(parents=True)

    assert malware._locate_binary("", "safe.bin", "../outside.zip", "repo1") is None


@pytest.mark.asyncio
async def test_lookup_route_requires_write_scope(mock_db):
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope

    auth = AuthContext(
        tenant_id="00000000-0000-0000-0000-000000000001",
        scopes={Scope.read},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/lookup", json={"query": "1.2.3.4"})

    app.dependency_overrides.clear()

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_webhook_dispatch_rejects_invalid_url(mock_db):
    from app.events.types import BaseEvent
    from app.models.webhooks import WebhookSubscription
    from app.workers.webhook import dispatch_webhooks

    sub = WebhookSubscription(
        tenant_id=uuid.uuid4(),
        url="http://127.0.0.1:8080/hook",
        filters={},
        active=True,
    )
    sub.id = uuid.uuid4()

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [sub]
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.add = MagicMock()
    mock_db.flush = AsyncMock()

    event = BaseEvent(event_type="entity.created", tenant_id=str(sub.tenant_id))
    await dispatch_webhooks(mock_db, event)

    delivery = mock_db.add.call_args[0][0]
    assert delivery.status == "failed"
    assert "Invalid webhook URL" in (delivery.error or "")


@pytest.mark.asyncio
async def test_token_exchange_sets_user_subject(client, mock_db):
    from app.auth.jwt import decode_access_token
    from app.models.auth import ApiKey

    raw_key = "test-api-key-12345"
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    api_key = ApiKey(
        tenant_id=tenant_id,
        user_id=user_id,
        key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
        name="test-key",
        active=True,
        scopes="read",
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = api_key
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await client.post("/api/v1/auth/token", json={"api_key": raw_key})

    assert resp.status_code == 200
    payload = decode_access_token(resp.json()["access_token"])
    assert payload["sub"] == str(user_id)
    assert payload["tenant_id"] == str(tenant_id)
