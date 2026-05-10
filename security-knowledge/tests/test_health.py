import pytest
from app.config import settings


@pytest.mark.asyncio
async def test_health_ok(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_healthz_ok(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "version": settings.APP_VERSION}
