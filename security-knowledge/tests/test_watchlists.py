"""Tests for watchlist defaults and tenant scope enforcement."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient


def _make_auth(tenant_id: str, user_id: str, scopes):
    from app.auth.dependencies import AuthContext

    return AuthContext(
        tenant_id=tenant_id,
        scopes=scopes,
        user_id=user_id,
        auth_type="bearer",
    )


@pytest.fixture
async def watchlist_client(mock_db, tenant_id):
    from app.auth.dependencies import get_auth
    from app.database import get_db
    from app.main import app

    from app.auth.dependencies import Scope

    auth = _make_auth(tenant_id, str(uuid.uuid4()), {Scope.watch, Scope.admin})
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_list_watchlists_respects_personal_scope_mode(watchlist_client, mock_db, monkeypatch, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist

    from app.routers import watchlists as watchlists_router

    user_id = str(uuid.uuid4())
    personal = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=uuid.UUID(user_id),
        created_by_user_id=uuid.UUID(user_id),
        name="My watchlist",
        scope="personal",
        expiry_hours=0,
        active=True,
    )
    personal.id = uuid.uuid4()
    personal.created_at = datetime.now(timezone.utc)
    personal.updated_at = personal.created_at
    personal.items = []

    org = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.UUID(user_id),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        active=True,
    )
    org.id = uuid.uuid4()
    org.created_at = datetime.now(timezone.utc)
    org.updated_at = org.created_at
    org.items = []

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"scope_mode": "personal"},
    )

    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    rows_result = MagicMock()
    rows_result.scalars.return_value.all.return_value = [personal, org]

    mock_db.execute = AsyncMock(side_effect=[tenant_result, tenant_result, rows_result])

    personal_helper = AsyncMock(return_value=personal)
    org_helper = AsyncMock(side_effect=AssertionError("org defaults should not be created in personal mode"))
    monkeypatch.setattr(watchlists_router, "get_or_create_default_personal_watchlist", personal_helper)
    monkeypatch.setattr(watchlists_router, "get_or_create_default_org_watchlist", org_helper)

    resp = await watchlist_client.get("/api/v1/watchlists")

    assert resp.status_code == 200
    data = resp.json()
    assert [w["scope"] for w in data["watchlists"]] == ["personal"]
    personal_helper.assert_awaited_once()
    org_helper.assert_not_called()


@pytest.mark.asyncio
async def test_create_watchlist_rejects_org_scope_when_disabled(watchlist_client, mock_db, tenant_id):
    from app.models.auth import Tenant

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"scope_mode": "personal"},
    )

    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    mock_db.execute = AsyncMock(return_value=tenant_result)
    mock_db.flush = AsyncMock()

    resp = await watchlist_client.post(
        "/api/v1/watchlists",
        json={"name": "Team watchlist", "scope": "org"},
    )

    assert resp.status_code == 403
    assert "disabled for this tenant" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_admin_create_org_watchlist(watchlist_client, mock_db, tenant_id):
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
    mock_db.flush = AsyncMock()

    resp = await watchlist_client.post(
        "/api/v1/admin/watchlists",
        json={"name": "Team watchlist", "expiry_hours": 24, "public_slug": "TLP-Green-IOC", "allow_unauthenticated": True},
    )

    assert resp.status_code == 201
    assert resp.json()["public_slug"] == "tlp-green-ioc"
    assert resp.json()["allow_unauthenticated"] is True


@pytest.mark.asyncio
async def test_move_watchlist_item_to_org_watchlist(watchlist_client, mock_db, tenant_id):
    from app.auth.dependencies import get_auth
    from app.main import app
    from app.models.pingback import IocWatch
    from app.models.watchlists import Watchlist

    auth = app.dependency_overrides[get_auth]()
    user_id = uuid.UUID(auth.user_id)

    watch = IocWatch(
        user_id=user_id,
        tenant_id=uuid.UUID(tenant_id),
        watchlist_id=uuid.uuid4(),
        ioc_kind="url",
        ioc_value_hash="a" * 64,
        ioc_value_display="https://example.com",
        mode="ping",
        active=True,
        notify_inbox=True,
        notify_email=False,
        sighting_count=0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    watch.id = uuid.uuid4()
    watch.watchlist = None
    watch.watchlist_id = None

    target = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.uuid4(),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        active=True,
    )
    target.id = uuid.uuid4()
    target.created_at = datetime.now(timezone.utc)
    target.updated_at = target.created_at

    watch_result = MagicMock()
    watch_result.scalar_one_or_none.return_value = watch
    target_result = MagicMock()
    target_result.scalar_one_or_none.return_value = target
    dup_result = MagicMock()
    dup_result.scalar_one_or_none.return_value = None

    mock_db.execute = AsyncMock(side_effect=[watch_result, target_result, dup_result])
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock()

    resp = await watchlist_client.patch(
        f"/api/v1/iocs/watches/{watch.id}",
        json={"watchlist_id": str(target.id)},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["watchlist_id"] == str(target.id)
    assert data["watchlist_name"] == "Org watchlist"


@pytest.mark.asyncio
async def test_update_watch_comment(watchlist_client, mock_db, tenant_id):
    from app.models.pingback import IocWatch
    from app.models.watchlists import Watchlist

    target = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.uuid4(),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        active=True,
    )
    target.id = uuid.uuid4()
    target.created_at = datetime.now(timezone.utc)
    target.updated_at = target.created_at

    watch = IocWatch(
        user_id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        watchlist_id=target.id,
        ioc_kind="url",
        ioc_value_hash="b" * 64,
        ioc_value_display="https://example.org",
        comment=None,
        mode="ping",
        active=True,
        notify_inbox=True,
        notify_email=False,
        sighting_count=0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    watch.id = uuid.uuid4()
    watch.watchlist = target

    watch_result = MagicMock()
    watch_result.scalar_one_or_none.return_value = watch

    mock_db.execute = AsyncMock(return_value=watch_result)
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock(return_value=None)

    resp = await watchlist_client.patch(
        f"/api/v1/iocs/watches/{watch.id}",
        json={"comment": "From vendor feed"},
    )

    assert resp.status_code == 200
    assert resp.json()["comment"] == "From vendor feed"


@pytest.mark.asyncio
async def test_public_watchlist_export_without_auth(client, mock_db, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist

    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.uuid4(),
        name="TLP Green IOC",
        scope="org",
        expiry_hours=0,
        export_formats={"json": True, "csv": False, "stix": False, "misp": False},
        public_slug="tlp-green-ioc",
        allow_unauthenticated=True,
        active=True,
    )
    watchlist.id = uuid.uuid4()
    watchlist.items = []

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"export_formats": {"json": True, "csv": False, "stix": False, "misp": False}},
    )

    watchlist_result = MagicMock()
    watchlist_result.scalar_one_or_none.return_value = watchlist
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    mock_db.execute = AsyncMock(side_effect=[watchlist_result, tenant_result])

    resp = await client.get("/api/v1/watchlists/public/tlp-green-ioc/export/json")

    assert resp.status_code == 200
    assert resp.json()["name"] == "TLP Green IOC"


@pytest.mark.asyncio
async def test_list_watchlists_includes_export_urls(watchlist_client, mock_db, monkeypatch, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist

    from app.routers import watchlists as watchlists_router

    user_id = str(uuid.uuid4())
    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=uuid.UUID(user_id),
        created_by_user_id=uuid.UUID(user_id),
        name="My watchlist",
        scope="personal",
        expiry_hours=0,
        active=True,
        export_formats={},
    )
    watchlist.id = uuid.uuid4()
    watchlist.created_at = datetime.now(timezone.utc)
    watchlist.updated_at = watchlist.created_at
    watchlist.items = []

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"scope_mode": "personal"},
    )

    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    rows_result = MagicMock()
    rows_result.scalars.return_value.all.return_value = [watchlist]

    mock_db.execute = AsyncMock(side_effect=[tenant_result, tenant_result, rows_result])

    personal_helper = AsyncMock(return_value=watchlist)
    org_helper = AsyncMock(side_effect=AssertionError("org defaults should not be created in personal mode"))
    monkeypatch.setattr(watchlists_router, "get_or_create_default_personal_watchlist", personal_helper)
    monkeypatch.setattr(watchlists_router, "get_or_create_default_org_watchlist", org_helper)

    resp = await watchlist_client.get("/api/v1/watchlists")

    assert resp.status_code == 200
    data = resp.json()
    exports = data["watchlists"][0]["exports"]
    assert set(exports) == {"json", "stix", "misp", "csv"}


@pytest.mark.asyncio
async def test_list_watchlists_includes_exports_from_tenant_defaults(watchlist_client, mock_db, monkeypatch, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist
    from app.routers import watchlists as watchlists_router

    user_id = str(uuid.uuid4())
    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.UUID(user_id),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        export_formats={},
        active=True,
    )
    watchlist.id = uuid.uuid4()
    watchlist.created_at = datetime.now(timezone.utc)
    watchlist.updated_at = watchlist.created_at
    watchlist.items = []

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={
            "scope_mode": "org",
            "export_formats": {"json": True, "stix": True, "misp": True, "csv": True},
        },
    )

    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant
    rows_result = MagicMock()
    rows_result.scalars.return_value.all.return_value = [watchlist]

    mock_db.execute = AsyncMock(side_effect=[tenant_result, rows_result, tenant_result])

    personal_helper = AsyncMock(side_effect=AssertionError("personal defaults should not be created in org mode"))
    org_helper = AsyncMock(return_value=watchlist)
    monkeypatch.setattr(watchlists_router, "get_or_create_default_personal_watchlist", personal_helper)
    monkeypatch.setattr(watchlists_router, "get_or_create_default_org_watchlist", org_helper)

    resp = await watchlist_client.get("/api/v1/watchlists")

    assert resp.status_code == 200
    data = resp.json()
    assert data["watchlists"][0]["exports"].keys() >= {"json", "stix", "misp", "csv"}


@pytest.mark.asyncio
async def test_export_watchlist_respects_tenant_export_formats(watchlist_client, mock_db, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist

    user_id = str(uuid.uuid4())
    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.UUID(user_id),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        export_formats={"json": True, "csv": True},
        active=True,
    )
    watchlist.id = uuid.uuid4()
    watchlist.items = []

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"export_formats": {"json": True, "csv": False, "stix": False, "misp": False}},
    )

    watchlist_result = MagicMock()
    watchlist_result.scalar_one_or_none.return_value = watchlist
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant

    mock_db.execute = AsyncMock(side_effect=[watchlist_result, tenant_result])

    resp = await watchlist_client.get(f"/api/v1/watchlists/{watchlist.id}/export/csv")

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_misp_export_uses_item_comment(watchlist_client, mock_db, tenant_id):
    from app.models.auth import Tenant
    from app.models.pingback import IocWatch
    from app.models.watchlists import Watchlist

    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.uuid4(),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        export_formats={"json": True, "csv": True, "stix": True, "misp": True},
        active=True,
    )
    watchlist.id = uuid.uuid4()
    watchlist.created_at = datetime.now(timezone.utc)
    watchlist.updated_at = watchlist.created_at

    item = IocWatch(
        user_id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        watchlist_id=watchlist.id,
        ioc_kind="url",
        ioc_value_hash="c" * 64,
        ioc_value_display="https://example.net",
        comment="Vendor intel",
        mode="ping",
        active=True,
        notify_inbox=True,
        notify_email=False,
        sighting_count=0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    item.id = uuid.uuid4()
    watchlist.items = [item]

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"export_formats": {"json": True, "csv": True, "stix": True, "misp": True}},
    )

    watchlist_result = MagicMock()
    watchlist_result.scalar_one_or_none.return_value = watchlist
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant

    mock_db.execute = AsyncMock(side_effect=[watchlist_result, tenant_result])

    resp = await watchlist_client.get(f"/api/v1/watchlists/{watchlist.id}/export/misp")

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["Event"]["Attribute"][0]["comment"] == "Vendor intel"


@pytest.mark.asyncio
async def test_delete_watchlist_as_admin(watchlist_client, mock_db, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist

    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.uuid4(),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        export_formats={},
        active=True,
    )
    watchlist.id = uuid.uuid4()
    watchlist.items = []

    watchlist_result = MagicMock()
    watchlist_result.scalar_one_or_none.return_value = watchlist
    mock_db.execute = AsyncMock(return_value=watchlist_result)
    mock_db.delete = AsyncMock()
    mock_db.flush = AsyncMock()

    resp = await watchlist_client.delete(f"/api/v1/watchlists/{watchlist.id}")

    assert resp.status_code == 204
    mock_db.delete.assert_awaited_once_with(watchlist)


@pytest.mark.asyncio
async def test_update_watchlist_public_settings(watchlist_client, mock_db, tenant_id):
    from app.models.auth import Tenant
    from app.models.watchlists import Watchlist

    watchlist = Watchlist(
        tenant_id=uuid.UUID(tenant_id),
        owner_user_id=None,
        created_by_user_id=uuid.uuid4(),
        name="Org watchlist",
        scope="org",
        expiry_hours=0,
        export_formats={"json": True, "csv": False, "stix": False, "misp": False},
        public_slug=None,
        allow_unauthenticated=False,
        active=True,
    )
    watchlist.id = uuid.uuid4()
    watchlist.items = []

    tenant = Tenant(
        id=uuid.UUID(tenant_id),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"export_formats": {"json": True, "csv": False, "stix": False, "misp": False}},
    )

    watchlist_result = MagicMock()
    watchlist_result.scalar_one_or_none.return_value = watchlist
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = tenant

    mock_db.execute = AsyncMock(side_effect=[watchlist_result, tenant_result])
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock(return_value=None)

    resp = await watchlist_client.patch(
        f"/api/v1/watchlists/{watchlist.id}",
        json={"public_slug": "TLP-Green-IOC", "allow_unauthenticated": True},
    )

    assert resp.status_code == 200
    assert resp.json()["public_slug"] == "tlp-green-ioc"
    assert resp.json()["allow_unauthenticated"] is True


def test_normalize_watchlist_expiry_defaults_and_caps():
    from app.models.auth import Tenant
    from app.services.watchlists import normalize_watchlist_expiry

    tenant = Tenant(
        id=uuid.uuid4(),
        name="Tenant",
        slug="tenant",
        active=True,
        watchlist_settings={"default_expiry_hours": 42, "max_expiry_hours": 100},
    )

    assert normalize_watchlist_expiry(None, tenant=tenant) == 42
    assert normalize_watchlist_expiry(0, tenant=tenant) == 0
    assert normalize_watchlist_expiry(250, tenant=tenant) == 100
