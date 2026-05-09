"""Tests for pingback: watch create, sighting trigger, inbox, contact."""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport


def _make_auth(tenant_id, user_id=None, scopes=None):
    from app.auth.dependencies import AuthContext, Scope
    if scopes is None:
        scopes = {Scope.watch, Scope.contact, Scope.read}
    return AuthContext(
        tenant_id=tenant_id,
        scopes=scopes,
        user_id=user_id or str(uuid.uuid4()),
        auth_type="bearer",
    )


@pytest.fixture
async def pingback_client(mock_db, tenant_id):
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth

    auth = _make_auth(tenant_id)
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


# ──────────────────────────────────────────────────────────────────────────────
# Watch tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_watch(pingback_client, mock_db):
    """POST /iocs/watches creates a watch."""
    from app.models.pingback import IocWatch
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    watch = MagicMock(spec=IocWatch)
    watch.id = uuid.uuid4()
    watch.ioc_kind = "ip"
    watch.ioc_value_display = "1.2.3.4"
    watch.mode = "ping"
    watch.active = True
    watch.sighting_count = 0
    watch.last_sighted_at = None
    watch.sector_context = None
    watch.created_at = now

    mock_db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock(side_effect=lambda obj: None)

    # After add+flush, mock the refreshed watch
    original_add = mock_db.add
    added_watches = []

    def capture_add(obj):
        if isinstance(obj, IocWatch):
            # Copy attributes to simulate DB persistence
            for attr in ["id", "ioc_kind", "ioc_value_display", "mode", "active", "sighting_count", "last_sighted_at", "sector_context", "created_at"]:
                setattr(obj, attr, getattr(watch, attr))
        original_add(obj)

    mock_db.add = capture_add
    mock_db.refresh = AsyncMock(return_value=None)

    resp = await pingback_client.post(
        "/api/v1/iocs/watches",
        json={"ioc_value": "1.2.3.4", "ioc_kind": "ip", "mode": "ping"},
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_list_watches_empty(pingback_client, mock_db):
    """GET /iocs/watches returns empty list."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await pingback_client.get("/api/v1/iocs/watches")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_delete_watch_not_found(pingback_client, mock_db):
    """DELETE /iocs/watches/{id} returns 404 if not found."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await pingback_client.delete(f"/api/v1/iocs/watches/{uuid.uuid4()}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_watch_success(pingback_client, mock_db):
    """DELETE /iocs/watches/{id} removes a watch."""
    from app.models.pingback import IocWatch

    watch = MagicMock(spec=IocWatch)
    watch.id = uuid.uuid4()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = watch
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.delete = AsyncMock()
    mock_db.flush = AsyncMock()

    resp = await pingback_client.delete(f"/api/v1/iocs/watches/{watch.id}")
    assert resp.status_code == 204
    mock_db.delete.assert_awaited_once_with(watch)


# ──────────────────────────────────────────────────────────────────────────────
# Inbox tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_inbox_empty(pingback_client, mock_db):
    """GET /inbox returns empty list."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await pingback_client.get("/api/v1/inbox")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_mark_inbox_read(pingback_client, mock_db):
    """PUT /inbox/{id}/read marks item as read."""
    from app.models.digests import InboxItem
    from datetime import datetime, timezone

    item = MagicMock(spec=InboxItem)
    item.id = uuid.uuid4()
    item.read = False

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = item
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    resp = await pingback_client.put(f"/api/v1/inbox/{item.id}/read")
    assert resp.status_code == 200
    assert item.read is True


# ──────────────────────────────────────────────────────────────────────────────
# Contact tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_contacts_empty(pingback_client, mock_db):
    """GET /iocs/contacts returns empty list."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)

    resp = await pingback_client.get("/api/v1/iocs/contacts")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_accept_contact(pingback_client, mock_db):
    """POST /iocs/contacts/{id}/accept sets status=accepted."""
    from app.models.pingback import IocContact

    contact = MagicMock(spec=IocContact)
    contact.id = uuid.uuid4()
    contact.status = "pending"

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = contact
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    resp = await pingback_client.post(
        f"/api/v1/iocs/contacts/{contact.id}/accept",
        json={"response": "Happy to connect."},
    )
    assert resp.status_code == 200
    assert contact.status == "accepted"


@pytest.mark.asyncio
async def test_decline_contact(pingback_client, mock_db):
    """POST /iocs/contacts/{id}/decline sets status=declined."""
    from app.models.pingback import IocContact

    contact = MagicMock(spec=IocContact)
    contact.id = uuid.uuid4()
    contact.status = "pending"

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = contact
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    resp = await pingback_client.post(f"/api/v1/iocs/contacts/{contact.id}/decline")
    assert resp.status_code == 200
    assert contact.status == "declined"


# ──────────────────────────────────────────────────────────────────────────────
# Pingback service unit test
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_and_notify_no_watches(mock_db):
    """check_and_notify returns 0 when no watches exist."""
    from app.services.pingback import check_and_notify

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute = AsyncMock(return_value=mock_result)

    count = await check_and_notify(
        ioc_value="8.8.8.8",
        ioc_kind="ip",
        trigger="enrichment",
        seeker_tenant_id=str(uuid.uuid4()),
        seeker_user_id=str(uuid.uuid4()),
        seeker_sector=None,
        seeker_comment=None,
        db=mock_db,
    )
    assert count == 0
