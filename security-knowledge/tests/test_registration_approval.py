"""Tests for registration, admin approval, and auth endpoints."""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
import bcrypt


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


@pytest.fixture
async def superadmin_client(mock_db, tenant_id):
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope

    auth = AuthContext(
        tenant_id=tenant_id,
        scopes={Scope.superadmin, Scope.admin, Scope.read, Scope.write},
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
    from app.auth.jwt import decode_token

    raw, key_hash = generate_api_key()
    api_key = MagicMock(spec=ApiKey)
    api_key.tenant_id = uuid.uuid4()
    api_key.user_id = uuid.uuid4()
    api_key.active = True

    import hashlib
    req_hash = hashlib.sha256(raw.encode()).hexdigest()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = api_key
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await open_client.post("/api/v1/auth/token", json={"api_key": raw})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    payload = decode_token(token)
    assert payload["sub"] == str(api_key.user_id)
    assert payload["tenant_id"] == str(api_key.tenant_id)


@pytest.mark.asyncio
async def test_post_token_requires_user_bound_key(open_client, mock_db):
    """Tenant-only API keys cannot be exchanged for bearer tokens."""
    from app.models.auth import ApiKey
    from app.auth.api_key import generate_api_key

    raw, key_hash = generate_api_key()
    api_key = MagicMock(spec=ApiKey)
    api_key.tenant_id = uuid.uuid4()
    api_key.user_id = None
    api_key.active = True

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = api_key
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await open_client.post("/api/v1/auth/token", json={"api_key": raw})
    assert resp.status_code == 403


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
async def test_register_personal_domain_gets_dedicated_tenant(open_client, mock_db):
    """Personal mailbox domains get a one-user tenant keyed to that user ID."""
    from app.models.auth import Tenant, User

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("bcrypt.hashpw", return_value=b"hashed"):
        resp = await open_client.post(
            "/api/v1/auth/register",
            json={
                "email": "person@gmail.com",
                "password": "secret123",
                "full_name": "Personal User",
                "business_sector": "Technology",
            },
        )

    assert resp.status_code == 201
    assert mock_db.add.call_count == 2
    tenant_obj = mock_db.add.call_args_list[0].args[0]
    user_obj = mock_db.add.call_args_list[1].args[0]
    assert isinstance(tenant_obj, Tenant)
    assert isinstance(user_obj, User)
    assert str(tenant_obj.id) == str(user_obj.id)
    assert str(user_obj.tenant_id) == str(user_obj.id)


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


@pytest.mark.asyncio
async def test_register_auto_approves_invited_email(open_client, mock_db):
    """Invited email addresses are auto-approved at registration."""
    from app.models.auth import Tenant, TenantInviteRule

    tenant = Tenant(id=uuid.uuid4(), name="Example", slug="example-com", active=True)
    invite = TenantInviteRule(
        tenant_id=tenant.id,
        created_by_user_id=None,
        rule_type="email",
        rule_value="vip@example.com",
        active=True,
    )

    existing_result = MagicMock()
    existing_result.scalar_one_or_none.return_value = None
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    invite_result = MagicMock()
    invite_result.scalars.return_value.all.return_value = [invite]
    mock_db.execute = AsyncMock(side_effect=[existing_result, tenant_result, invite_result])
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("bcrypt.hashpw", return_value=b"hashed"):
        resp = await open_client.post(
            "/api/v1/auth/register",
            json={
                "email": "vip@example.com",
                "password": "SuperSecret123",
                "full_name": "VIP User",
                "business_sector": "Technology",
            },
        )

    assert resp.status_code == 201
    assert resp.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_register_auto_approves_invited_domain(open_client, mock_db):
    """Invited domains are auto-approved at registration."""
    from app.models.auth import Tenant, TenantInviteRule

    tenant = Tenant(id=uuid.uuid4(), name="Example", slug="example-com", active=True)
    invite = TenantInviteRule(
        tenant_id=tenant.id,
        created_by_user_id=None,
        rule_type="domain",
        rule_value="example.com",
        active=True,
    )

    existing_result = MagicMock()
    existing_result.scalar_one_or_none.return_value = None
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    invite_result = MagicMock()
    invite_result.scalars.return_value.all.return_value = [invite]
    mock_db.execute = AsyncMock(side_effect=[existing_result, tenant_result, invite_result])
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("bcrypt.hashpw", return_value=b"hashed"):
        resp = await open_client.post(
            "/api/v1/auth/register",
            json={
                "email": "someone@example.com",
                "password": "SuperSecret123",
                "full_name": "Invited User",
                "business_sector": "Technology",
            },
        )

    assert resp.status_code == 201
    assert resp.json()["status"] == "approved"


# ──────────────────────────────────────────────────────────────────────────────
# Admin user approval
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_approve_user(admin_client, mock_db):
    """POST /admin/users/{id}/approve sets user status to approved."""
    from app.models.auth import User
    from app.models.auth import Tenant

    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.tenant_id = uuid.uuid4()
    user.status = "pending"
    tenant = MagicMock(spec=Tenant)
    tenant.watchlist_settings = {"scope_mode": "both"}

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    mock_db.execute = AsyncMock(side_effect=[mock_result, count_result, tenant_result])
    mock_db.flush = AsyncMock()

    with patch("app.routers.admin.get_or_create_default_personal_watchlist", AsyncMock()) as personal_watchlist, patch(
        "app.routers.admin.get_or_create_default_org_watchlist", AsyncMock()
    ) as org_watchlist:
        resp = await admin_client.post(
            f"/api/v1/admin/users/{user.id}/approve",
            json={"action": "approve"},
        )

    assert resp.status_code == 200
    assert user.status == "approved"
    assert personal_watchlist.await_count == 1
    assert org_watchlist.await_count == 1


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


@pytest.mark.asyncio
async def test_admin_reset_password(admin_client, mock_db, tenant_id):
    """POST /admin/users/{id}/reset-password updates password hash."""
    from app.models.auth import User

    user = User(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        email="reset@example.com",
        hashed_password=bcrypt.hashpw("OldPassword123".encode(), bcrypt.gensalt()).decode(),
        full_name="Reset User",
        business_sector="Technology",
        status="approved",
        role="user",
        active=True,
    )
    original_hash = user.hashed_password

    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=result)
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    resp = await admin_client.post(
        f"/api/v1/admin/users/{user.id}/reset-password",
        json={"new_password": "NewPassword456"},
    )

    assert resp.status_code == 200
    assert user.hashed_password != original_hash
    assert bcrypt.checkpw("NewPassword456".encode(), user.hashed_password.encode())


@pytest.mark.asyncio
async def test_admin_manage_invites(admin_client, mock_db, tenant_id):
    """Admin can list/create/delete invite rules."""
    from app.models.auth import TenantInviteRule
    from datetime import datetime, timezone

    existing = TenantInviteRule(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        created_by_user_id=None,
        rule_type="domain",
        rule_value="example.com",
        active=True,
    )
    existing.created_at = datetime.now(timezone.utc)

    list_result = MagicMock()
    list_result.scalars.return_value.all.return_value = [existing]
    none_result = MagicMock()
    none_result.scalar_one_or_none.return_value = None
    delete_result = MagicMock()
    delete_result.scalar_one_or_none.return_value = existing

    mock_db.execute = AsyncMock(side_effect=[list_result, none_result, delete_result])
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.delete = AsyncMock()

    listed = await admin_client.get("/api/v1/admin/invites")
    created = await admin_client.post("/api/v1/admin/invites", json={"rule_type": "email", "rule_value": "a@b.com"})
    deleted = await admin_client.delete(f"/api/v1/admin/invites/{existing.id}")

    assert listed.status_code == 200
    assert listed.json()[0]["rule_value"] == "example.com"
    assert created.status_code == 201
    assert created.json()["rule_type"] == "email"
    assert deleted.status_code == 204


@pytest.mark.asyncio
async def test_admin_list_users_active_alias(admin_client, mock_db, tenant_id):
    """GET /admin/users?status=active maps to approved for backward compatibility."""
    from app.models.auth import User
    from datetime import datetime, timezone

    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = "approved@example.com"
    user.full_name = "Approved User"
    user.business_sector = "Technology"
    user.status = "approved"
    user.role = "user"
    user.tenant_id = uuid.UUID(tenant_id)
    user.created_at = datetime.now(timezone.utc)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [user]
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await admin_client.get("/api/v1/admin/users?status=active")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["status"] == "approved"


@pytest.mark.asyncio
async def test_admin_list_users_invalid_status(admin_client):
    """GET /admin/users rejects unsupported status values."""
    resp = await admin_client.get("/api/v1/admin/users?status=unknown")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_admin_list_tenants_forbidden_for_admin(admin_client):
    """GET /admin/tenants requires superadmin."""
    resp = await admin_client.get("/api/v1/admin/tenants")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_tenants_superadmin(superadmin_client, mock_db):
    """GET /admin/tenants returns tenant rows for superadmin."""
    from app.models.auth import Tenant
    from datetime import datetime, timezone

    t = MagicMock(spec=Tenant)
    t.id = uuid.uuid4()
    t.name = "Tenant A"
    t.slug = "tenant-a"
    t.active = True
    t.created_at = datetime.now(timezone.utc)

    first = MagicMock()
    first.scalars.return_value.all.return_value = [t]
    second = MagicMock()
    second.scalar_one.return_value = 7
    mock_db.execute = AsyncMock(side_effect=[first, second])

    resp = await superadmin_client.get("/api/v1/admin/tenants")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["slug"] == "tenant-a"


@pytest.mark.asyncio
async def test_admin_watchlist_settings_legacy_alias(admin_client, mock_db, tenant_id):
    from app.models.auth import Tenant

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"scope_mode": "both"},
    )

    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    mock_db.execute = AsyncMock(return_value=tenant_result)

    resp = await admin_client.get("/api/v1/admin/settings/watchlist")

    assert resp.status_code == 200
    assert resp.json()["scope_mode"] == "both"


@pytest.mark.asyncio
async def test_admin_move_user_tenant(superadmin_client, mock_db, tenant_id):
    """POST /admin/users/{id}/tenant updates user and related key tenant IDs."""
    from app.models.auth import User, Tenant, ApiKey, UserProviderKey

    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = "u@example.com"
    user.tenant_id = uuid.UUID(tenant_id)

    tenant = MagicMock(spec=Tenant)
    tenant.id = uuid.uuid4()

    api_key = MagicMock(spec=ApiKey)
    api_key.user_id = user.id
    api_key.tenant_id = user.tenant_id
    provider_key = MagicMock(spec=UserProviderKey)
    provider_key.user_id = user.id
    provider_key.tenant_id = user.tenant_id

    user_result = MagicMock()
    user_result.scalar_one_or_none.return_value = user
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    api_key_result = MagicMock()
    api_key_result.scalars.return_value.all.return_value = [api_key]
    provider_key_result = MagicMock()
    provider_key_result.scalars.return_value.all.return_value = [provider_key]
    mock_db.execute = AsyncMock(side_effect=[user_result, tenant_result, api_key_result, provider_key_result])
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    resp = await superadmin_client.post(
        f"/api/v1/admin/users/{user.id}/tenant",
        json={"tenant_id": str(tenant.id)},
    )
    assert resp.status_code == 200
    assert str(user.tenant_id) == str(tenant.id)
    assert str(api_key.tenant_id) == str(tenant.id)
    assert str(provider_key.tenant_id) == str(tenant.id)


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
