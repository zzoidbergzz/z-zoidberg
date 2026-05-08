"""Tests for registration, admin approval, and auth endpoints."""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport


@pytest.fixture
async def open_client(mock_db):
    """Client with only DB overridden (no auth override)."""
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
async def admin_client(mock_db, tenant_id):
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope

    auth = AuthContext(
        tenant_id=tenant_id,
        scopes={Scope.admin, Scope.read, Scope.write},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


# ──────────────────────────────────────────────────────────────────────────────
# POST /auth/token
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_post_token_valid(open_client, mock_db):
    """POST /auth/token with valid API key returns JWT."""
    from app.models.auth import ApiKey
    from app.auth.api_key import generate_api_key

    raw, key_hash = generate_api_key()
    api_key = MagicMock(spec=ApiKey)
    api_key.tenant_id = uuid.uuid4()
    api_key.active = True

    import hashlib
    req_hash = hashlib.sha256(raw.encode()).hexdigest()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = api_key
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await open_client.post("/api/v1/auth/token", json={"api_key": raw})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_post_token_invalid(open_client, mock_db):
    """POST /auth/token with invalid API key returns 401."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await open_client.post("/api/v1/auth/token", json={"api_key": "bad-key"})
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# POST /auth/register
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_new_user(open_client, mock_db):
    """POST /auth/register creates a pending user."""
    from app.models.auth import User, Tenant
    import uuid

    # No existing user
    call_count = 0
    new_user = MagicMock(spec=User)
    new_user.id = uuid.uuid4()
    new_user.email = "test@example.com"
    new_user.status = "pending"

    async def fake_execute(q, *a, **kw):
        nonlocal call_count
        m = MagicMock()
        call_count += 1
        if call_count == 1:
            # Email uniqueness check
            m.scalar_one_or_none.return_value = None
        elif call_count == 2:
            # Tenant lookup
            m.scalar_one_or_none.return_value = None
        else:
            m.scalar_one_or_none.return_value = None
        return m

    mock_db.execute = fake_execute
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock(side_effect=lambda obj: setattr(obj, "id", uuid.uuid4()) or setattr(obj, "email", "test@example.com") or setattr(obj, "status", "pending"))

    with patch("bcrypt.hashpw", return_value=b"hashed"):
        resp = await open_client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@example.com",
                "password": "secret123",
                "full_name": "Test User",
                "business_sector": "Technology",
            },
        )

    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_register_duplicate_email(open_client, mock_db):
    """POST /auth/register with duplicate email returns 409."""
    from app.models.auth import User

    existing = MagicMock(spec=User)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await open_client.post(
        "/api/v1/auth/register",
        json={"email": "existing@example.com", "password": "pass"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_invalid_sector(open_client, mock_db):
    """POST /auth/register with invalid business_sector returns 422."""
    resp = await open_client.post(
        "/api/v1/auth/register",
        json={"email": "x@y.com", "password": "p", "business_sector": "INVALID"},
    )
    assert resp.status_code == 422


# ──────────────────────────────────────────────────────────────────────────────
# Admin user approval
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_approve_user(admin_client, mock_db):
    """POST /admin/users/{id}/approve sets user status to approved."""
    from app.models.auth import User

    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.status = "pending"

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    resp = await admin_client.post(
        f"/api/v1/admin/users/{user.id}/approve",
        json={"action": "approve"},
    )
    assert resp.status_code == 200
    assert user.status == "approved"


@pytest.mark.asyncio
async def test_admin_approve_user_not_found(admin_client, mock_db):
    """POST /admin/users/{id}/approve returns 404 if user not found."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await admin_client.post(
        f"/api/v1/admin/users/{uuid.uuid4()}/approve",
        json={"action": "approve"},
    )
    assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# GET /admin/stats
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_stats(admin_client, mock_db):
    """GET /admin/stats returns counts."""
    call_count = 0

    async def fake_execute(q, *a, **kw):
        nonlocal call_count
        m = MagicMock()
        call_count += 1
        m.scalar_one.return_value = call_count * 10
        return m

    mock_db.execute = fake_execute
    resp = await admin_client.get("/api/v1/admin/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "user_count" in data
    assert "watch_count" in data
    assert "sighting_count" in data
    assert "enrichment_cache_size" in data


# ──────────────────────────────────────────────────────────────────────────────
# GET/PATCH /auth/me
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_me(mock_db, tenant_id):
    """GET /auth/me returns user profile."""
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope
    from app.models.auth import User
    from datetime import datetime, timezone

    uid = str(uuid.uuid4())
    user = MagicMock(spec=User)
    user.id = uuid.UUID(uid)
    user.email = "me@example.com"
    user.full_name = "Me"
    user.business_sector = "Technology"
    user.status = "approved"
    user.role = "user"
    user.tenant_id = uuid.UUID(tenant_id)
    user.created_at = datetime.now(timezone.utc)

    auth = AuthContext(tenant_id=tenant_id, scopes={Scope.read}, user_id=uid, auth_type="bearer")
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/v1/auth/me")

    app.dependency_overrides.clear()
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "me@example.com"
    assert data["business_sector"] == "Technology"


@pytest.mark.asyncio
async def test_patch_me(mock_db, tenant_id):
    """PATCH /auth/me updates full_name and business_sector."""
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope
    from app.models.auth import User
    from datetime import datetime, timezone

    uid = str(uuid.uuid4())
    user = MagicMock(spec=User)
    user.id = uuid.UUID(uid)
    user.email = "me@example.com"
    user.full_name = "Old Name"
    user.business_sector = "UK-General"
    user.status = "approved"
    user.role = "user"
    user.tenant_id = uuid.UUID(tenant_id)
    user.created_at = datetime.now(timezone.utc)

    auth = AuthContext(tenant_id=tenant_id, scopes={Scope.read}, user_id=uid, auth_type="bearer")
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock(return_value=None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.patch(
            "/api/v1/auth/me",
            json={"full_name": "New Name", "business_sector": "Healthcare"},
        )

    app.dependency_overrides.clear()
    assert resp.status_code == 200
    assert user.full_name == "New Name"
    assert user.business_sector == "Healthcare"
