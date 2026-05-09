"""UI route access tests."""

import uuid

import pytest


@pytest.mark.asyncio
async def test_admin_page_redirects_non_admin(client):
    from app.auth.jwt import create_access_token
    from app.config import settings

    token = create_access_token(
        {
            "sub": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "email": "user@example.com",
            "role": "user",
        }
    )
    client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await client.get("/admin", follow_redirects=False)

    assert resp.status_code in {301, 302, 307}
    assert resp.headers["location"] == "/"


@pytest.mark.asyncio
async def test_admin_page_allows_admin(client):
    from app.auth.jwt import create_access_token
    from app.config import settings

    token = create_access_token(
        {
            "sub": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "email": "admin@example.com",
            "role": "admin",
        }
    )
    client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await client.get("/admin")

    assert resp.status_code == 200
