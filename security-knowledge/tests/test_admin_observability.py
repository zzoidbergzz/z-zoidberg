from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_admin_migration_state_endpoint(mock_db):
    from app.auth.dependencies import AuthContext, Scope, get_auth
    from app.database import get_db
    from app.main import app

    result = MagicMock()
    result.scalar_one_or_none.return_value = "0037_pgvector_embeddings"
    mock_db.execute = AsyncMock(return_value=result)

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: AuthContext(
        tenant_id=str(uuid.uuid4()),
        scopes={Scope.admin},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get("/api/v1/admin/migrations/state")
        assert resp.status_code == 200
        body = resp.json()
        assert "current_revision" in body
        assert "head_revision" in body
        assert "pending_migrations" in body
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_admin_slow_queries_disabled_without_extension(mock_db):
    from app.auth.dependencies import AuthContext, Scope, get_auth
    from app.database import get_db
    from app.main import app

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: AuthContext(
        tenant_id=str(uuid.uuid4()),
        scopes={Scope.admin},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get("/api/v1/admin/slow-queries")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
    finally:
        app.dependency_overrides.clear()
