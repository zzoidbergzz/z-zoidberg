"""Test configuration and fixtures."""
import pytest
import structlog
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock
import uuid


@pytest.fixture(autouse=True)
def reset_structlog():
    """Reset structlog to a safe test configuration before every test.

    When the full test suite runs, tests that import app.main trigger
    configure_logging() which adds `add_logger_name` to the structlog
    processor chain.  That processor calls `logger.name` which doesn't
    exist on structlog's own PrintLogger, causing AttributeError in
    subsequent tests.  Resetting to a simple processor chain here
    avoids the cross-test pollution.
    """
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
    yield


@pytest.fixture
def tenant_id():
    return str(uuid.uuid4())


@pytest.fixture
def api_key_value():
    return "test-api-key-12345"


@pytest.fixture
def auth_headers(api_key_value):
    return {"X-API-Key": api_key_value}


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.execute = AsyncMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    db.add = MagicMock()
    db.rollback = AsyncMock()
    db.close = AsyncMock()
    return db


@pytest.fixture
async def client(mock_db, tenant_id, api_key_value):
    """HTTP test client with mocked auth and DB."""
    import hashlib
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import require_read, require_write

    auth_payload = {"tenant_id": tenant_id, "sub": tenant_id}

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[require_read] = lambda: auth_payload
    app.dependency_overrides[require_write] = lambda: auth_payload

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


# Fixture data
@pytest.fixture
def sample_entity_data():
    return {"name": "CVE-2024-1234", "kind": "cve", "description": "Test CVE", "confidence": 70}


@pytest.fixture
def sample_claim_data():
    return {"subject": "CVE-2024-1234", "predicate": "affects", "object": "OpenSSL", "confidence": 80}
