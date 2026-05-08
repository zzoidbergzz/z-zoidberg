"""Tests for sector endpoints."""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport


@pytest.fixture
async def sector_client(mock_db, tenant_id):
    """HTTP test client with admin-level auth."""
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope

    admin_ctx = AuthContext(
        tenant_id=tenant_id,
        scopes={Scope.read, Scope.write, Scope.admin},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: admin_ctx

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


def _make_sector(slug="financial-banking", name="Financial & Banking"):
    from app.models.sectors import Sector
    s = MagicMock(spec=Sector)
    s.id = uuid.uuid4()
    s.slug = slug
    s.name = name
    s.description = None
    s.isac_name = "FS-ISAC"
    s.info_sharing_enabled = True
    s.active = True
    s.member_count = 3
    return s


@pytest.mark.asyncio
async def test_list_sectors_public(mock_db):
    """GET /sectors should return list without auth."""
    from app.main import app
    from app.database import get_db

    sector = _make_sector()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [sector]
    mock_db.execute = AsyncMock(return_value=mock_result)

    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/v1/sectors")

    app.dependency_overrides.clear()
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data[0]["slug"] == "financial-banking"


@pytest.mark.asyncio
async def test_get_sector_not_found(mock_db):
    """GET /sectors/{slug} returns 404 for unknown slug."""
    from app.main import app
    from app.database import get_db

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/v1/sectors/nonexistent")

    app.dependency_overrides.clear()
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_join_sector_requires_auth(mock_db):
    """POST /sectors/{slug}/join requires auth."""
    from app.main import app
    from app.database import get_db

    # No auth override — should fail
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/sectors/financial-banking/join")

    app.dependency_overrides.clear()
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_list_sectors(sector_client, mock_db):
    """GET /admin/sectors returns list with pending counts."""
    sector = _make_sector()
    calls = []

    async def fake_execute(q, *a, **kw):
        m = MagicMock()
        calls.append(len(calls))
        if len(calls) == 1:
            m.scalars.return_value.all.return_value = [sector]
        else:
            m.scalar_one.return_value = 0
        return m

    mock_db.execute = fake_execute
    resp = await sector_client.get("/api/v1/admin/sectors")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_admin_approve_member(sector_client, mock_db):
    """POST /admin/sectors/{slug}/members/{uid}/approve approves membership."""
    from app.models.sectors import Sector, SectorMembership

    sector = _make_sector()
    mem = MagicMock(spec=SectorMembership)
    mem.status = "pending"

    call_count = 0

    async def fake_execute(q, *a, **kw):
        nonlocal call_count
        m = MagicMock()
        call_count += 1
        if call_count == 1:
            m.scalar_one_or_none.return_value = sector  # sector lookup
        elif call_count == 2:
            m.scalar_one_or_none.return_value = mem  # membership lookup
        else:
            m.scalar_one_or_none.return_value = None
        return m

    mock_db.execute = fake_execute
    user_id = uuid.uuid4()
    resp = await sector_client.post(
        f"/api/v1/admin/sectors/financial-banking/members/{user_id}/approve",
        json={"action": "approve"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_sector_invite_flow(sector_client, mock_db):
    """POST /admin/sectors/{slug}/invite creates invite token."""
    sector = _make_sector()
    call_count = 0

    async def fake_execute(q, *a, **kw):
        nonlocal call_count
        m = MagicMock()
        call_count += 1
        if call_count == 1:
            m.scalar_one_or_none.return_value = sector  # sector lookup
        else:
            m.scalar_one_or_none.return_value = None
        return m

    mock_db.execute = fake_execute
    mock_db.flush = AsyncMock()

    resp = await sector_client.post(
        "/api/v1/admin/sectors/financial-banking/invite",
        json={"email": "newuser@example.com"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "invite_token" in data
    assert data["email"] == "newuser@example.com"
