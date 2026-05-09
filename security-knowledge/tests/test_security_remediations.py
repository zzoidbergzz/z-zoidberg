from __future__ import annotations

from pathlib import Path
import uuid

import pytest
from httpx import AsyncClient, ASGITransport


def test_lookup_ioc_registered_write_scope():
    import app.mcp.tools.lookup_ioc  # noqa: F401
    from app.mcp.registry import get_tool

    tool = get_tool("lookup_ioc")
    assert tool is not None
    assert tool.scope == "write"


def test_mcp_build_auth_uses_supplied_scopes():
    from app.auth.dependencies import Scope
    from app.mcp.server import _build_auth

    auth = _build_auth(scopes={Scope.read})
    assert Scope.read in auth.scopes
    assert Scope.write not in auth.scopes


def test_malware_locate_standalone_blocks_traversal(monkeypatch, tmp_path):
    import importlib
    from app.routers import malware

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    importlib.reload(malware)
    repo_root = tmp_path / "z-zoidberg" / "repos" / "repo1"
    repo_root.mkdir(parents=True)
    (repo_root / "safe.bin").write_bytes(b"safe")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")

    assert malware._locate_standalone("", "../outside.txt", "repo1") is None
    assert malware._locate_standalone("", "safe.bin", "repo1") == b"safe"


@pytest.mark.asyncio
async def test_lookup_route_requires_write_scope(mock_db):
    from app.main import app
    from app.database import get_db
    from app.auth.dependencies import get_auth, AuthContext, Scope

    auth = AuthContext(
        tenant_id="00000000-0000-0000-0000-000000000001",
        scopes={Scope.read},
        user_id=str(uuid.uuid4()),
        auth_type="bearer",
    )

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_auth] = lambda: auth

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/lookup", json={"query": "1.2.3.4"})

    app.dependency_overrides.clear()

    assert resp.status_code == 403
