from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_capabilities_requires_admin():
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/v1/capabilities")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_capabilities_allows_admin():
    from app.auth.dependencies import AuthContext, Scope, require_admin
    from app.main import app

    app.dependency_overrides[require_admin] = lambda: AuthContext(
        tenant_id=str(uuid.uuid4()),
        scopes={Scope.admin},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get("/api/v1/capabilities")
        assert resp.status_code == 200
        body = resp.json()
        assert "version" in body
        assert "feature_flags" in body
    finally:
        app.dependency_overrides.clear()
