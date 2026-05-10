from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_security_headers_present(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers["content-security-policy"]
    assert resp.headers["strict-transport-security"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
