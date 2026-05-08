"""Tests for the Dark-Moon MCP bridge.

All tests mock the subprocess/MCP client so the real Dark-Moon server
and Docker container are NOT required.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_tool(name: str, description: str = "", schema: dict | None = None):
    """Return a minimal MCP Tool-like object."""
    t = MagicMock()
    t.name = name
    t.description = description
    t.inputSchema = schema or {"type": "object", "properties": {}}
    return t


def _make_content(text: str):
    c = MagicMock()
    c.text = text
    return c


# ---------------------------------------------------------------------------
# Bridge unit tests
# ---------------------------------------------------------------------------


def test_dark_moon_enabled_flag_default_false(monkeypatch):
    """DARK_MOON_ENABLED defaults to false."""
    monkeypatch.delenv("DARK_MOON_ENABLED", raising=False)
    # Re-import to pick up env change — evaluate the expression directly.
    import importlib
    import app.mcp.dark_moon_bridge as bridge
    importlib.reload(bridge)
    assert bridge.DARK_MOON_ENABLED is False


def test_register_dark_moon_tools_skipped_when_disabled(monkeypatch):
    """register_dark_moon_tools() is a no-op when disabled."""
    monkeypatch.setenv("DARK_MOON_ENABLED", "false")

    import importlib
    import app.mcp.dark_moon_bridge as bridge
    importlib.reload(bridge)

    with patch("app.mcp.registry.register_tool") as mock_reg:
        bridge.register_dark_moon_tools()
    mock_reg.assert_not_called()


def test_register_tools_uses_dm_prefix():
    """_register_tools() prefixes every tool name with dm_."""
    import app.mcp.dark_moon_bridge as bridge

    fake_tools = [
        {"name": "health_check", "description": "Health", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "list_workflows", "description": "Workflows", "inputSchema": {"type": "object", "properties": {}}},
    ]

    registered: list[str] = []

    def fake_register(name, fn, schema, description, scope):
        registered.append(name)

    with patch("app.mcp.registry.register_tool", side_effect=fake_register):
        bridge.registered_dm_tools.clear()
        bridge._register_tools(fake_tools)

    assert "dm_health_check" in registered
    assert "dm_list_workflows" in registered
    assert all(n.startswith("dm_") for n in registered)


def test_register_tools_description_prefix():
    """Registered descriptions are prefixed with [Dark-Moon]."""
    import app.mcp.dark_moon_bridge as bridge

    fake_tools = [
        {"name": "diagnose", "description": "Run diagnostics", "inputSchema": {}},
    ]

    captured: dict = {}

    def fake_register(name, fn, schema, description, scope):
        captured[name] = description

    with patch("app.mcp.registry.register_tool", side_effect=fake_register):
        bridge.registered_dm_tools.clear()
        bridge._register_tools(fake_tools)

    assert captured["dm_diagnose"].startswith("[Dark-Moon]")
    assert "Run diagnostics" in captured["dm_diagnose"]


def test_register_tools_scope_is_write():
    """All Dark-Moon tools are registered with write scope (they touch external systems)."""
    import app.mcp.dark_moon_bridge as bridge

    captured_scopes: list[str] = []

    def fake_register(name, fn, schema, description, scope):
        captured_scopes.append(scope)

    with patch("app.mcp.registry.register_tool", side_effect=fake_register):
        bridge.registered_dm_tools.clear()
        bridge._register_tools(bridge._FALLBACK_TOOLS)

    assert all(s == "write" for s in captured_scopes)


def test_fallback_tools_cover_known_upstream():
    """The fallback tool list contains all 8 tools known from the upstream source."""
    import app.mcp.dark_moon_bridge as bridge

    names = {t["name"] for t in bridge._FALLBACK_TOOLS}
    expected = {
        "get_session",
        "health_check",
        "check_tool",
        "diagnose",
        "execute_command",
        "list_allowed_tools",
        "list_workflows",
        "run_workflow",
    }
    assert expected == names


@pytest.mark.asyncio
async def test_invoke_dark_moon_tool_success():
    """_invoke_dark_moon_tool returns result dict on success."""
    import app.mcp.dark_moon_bridge as bridge

    mock_result = MagicMock()
    mock_result.isError = False
    mock_result.content = [_make_content('{"healthy": true}')]

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock(return_value=None)
    mock_session.call_tool = AsyncMock(return_value=mock_result)

    mock_cm_session = AsyncMock()
    mock_cm_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm_session.__aexit__ = AsyncMock(return_value=False)

    mock_streams = (AsyncMock(), AsyncMock())
    mock_cm_client = AsyncMock()
    mock_cm_client.__aenter__ = AsyncMock(return_value=mock_streams)
    mock_cm_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.mcp.dark_moon_bridge.stdio_client", return_value=mock_cm_client):
        with patch("app.mcp.dark_moon_bridge.ClientSession", return_value=mock_cm_session):
            result = await bridge._invoke_dark_moon_tool("health_check", {})

    assert result == {"result": '{"healthy": true}'}


@pytest.mark.asyncio
async def test_invoke_dark_moon_tool_error_flag():
    """_invoke_dark_moon_tool returns error dict when isError=True."""
    import app.mcp.dark_moon_bridge as bridge

    mock_result = MagicMock()
    mock_result.isError = True
    mock_result.content = [_make_content("container not running")]

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock(return_value=None)
    mock_session.call_tool = AsyncMock(return_value=mock_result)

    mock_cm_session = AsyncMock()
    mock_cm_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm_session.__aexit__ = AsyncMock(return_value=False)

    mock_streams = (AsyncMock(), AsyncMock())
    mock_cm_client = AsyncMock()
    mock_cm_client.__aenter__ = AsyncMock(return_value=mock_streams)
    mock_cm_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.mcp.dark_moon_bridge.stdio_client", return_value=mock_cm_client):
        with patch("app.mcp.dark_moon_bridge.ClientSession", return_value=mock_cm_session):
            result = await bridge._invoke_dark_moon_tool("health_check", {})

    assert "error" in result
    assert "container not running" in result["error"]


@pytest.mark.asyncio
async def test_invoke_dark_moon_tool_exception():
    """_invoke_dark_moon_tool catches exceptions and returns error dict."""
    import app.mcp.dark_moon_bridge as bridge

    mock_cm_client = AsyncMock()
    mock_cm_client.__aenter__ = AsyncMock(side_effect=OSError("no such file"))
    mock_cm_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.mcp.dark_moon_bridge.stdio_client", return_value=mock_cm_client):
        result = await bridge._invoke_dark_moon_tool("get_session", {})

    assert "error" in result
    assert "no such file" in result["error"]


@pytest.mark.asyncio
async def test_discover_tools_returns_fallback_on_failure():
    """_discover_tools() returns fallback list when subprocess fails."""
    import app.mcp.dark_moon_bridge as bridge

    mock_cm_client = AsyncMock()
    mock_cm_client.__aenter__ = AsyncMock(side_effect=FileNotFoundError("python not found"))
    mock_cm_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.mcp.dark_moon_bridge.stdio_client", return_value=mock_cm_client):
        result = await bridge._discover_tools()

    assert result == bridge._FALLBACK_TOOLS


@pytest.mark.asyncio
async def test_discover_tools_parses_tool_list():
    """_discover_tools() properly maps upstream tool list to dicts."""
    import app.mcp.dark_moon_bridge as bridge

    upstream_tools = [
        _make_mock_tool("health_check", "Health", {"type": "object", "properties": {}}),
        _make_mock_tool("run_workflow", "Run", {"type": "object", "properties": {"workflow": {"type": "string"}}}),
    ]
    # Make inputSchema behave as dict (not model_dump path)
    for t in upstream_tools:
        t.inputSchema = t.inputSchema  # already a plain dict

    mock_list_result = MagicMock()
    mock_list_result.tools = upstream_tools

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock(return_value=None)
    mock_session.list_tools = AsyncMock(return_value=mock_list_result)

    mock_cm_session = AsyncMock()
    mock_cm_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm_session.__aexit__ = AsyncMock(return_value=False)

    mock_streams = (AsyncMock(), AsyncMock())
    mock_cm_client = AsyncMock()
    mock_cm_client.__aenter__ = AsyncMock(return_value=mock_streams)
    mock_cm_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.mcp.dark_moon_bridge.stdio_client", return_value=mock_cm_client):
        with patch("app.mcp.dark_moon_bridge.ClientSession", return_value=mock_cm_session):
            result = await bridge._discover_tools()

    assert len(result) == 2
    assert result[0]["name"] == "health_check"
    assert result[1]["name"] == "run_workflow"


def test_make_tool_fn_returns_callable():
    """_make_tool_fn returns a callable async function with correct __name__."""
    import app.mcp.dark_moon_bridge as bridge
    import inspect

    fn = bridge._make_tool_fn("health_check")
    assert callable(fn)
    assert inspect.iscoroutinefunction(fn)
    assert fn.__name__ == "dm_health_check"


@pytest.mark.asyncio
async def test_registered_tool_fn_forwards_to_invoke():
    """A registered dm_* tool fn calls _invoke_dark_moon_tool with correct upstream name."""
    import app.mcp.dark_moon_bridge as bridge

    captured: list[tuple] = []

    async def fake_invoke(tool_name: str, args: dict):
        captured.append((tool_name, args))
        return {"result": "ok"}

    fn = bridge._make_tool_fn("list_workflows")

    mock_db = AsyncMock()
    mock_auth = MagicMock()

    with patch.object(bridge, "_invoke_dark_moon_tool", side_effect=fake_invoke):
        result = await fn({"extra": 1}, mock_db, mock_auth)

    assert captured == [("list_workflows", {"extra": 1})]
    assert result == {"result": "ok"}


def test_extract_text_joins_content():
    """_extract_text joins multiple content items with newlines."""
    import app.mcp.dark_moon_bridge as bridge

    items = [_make_content("line1"), _make_content("line2")]
    assert bridge._extract_text(items) == "line1\nline2"


def test_extract_text_empty():
    """_extract_text returns empty string for empty content."""
    import app.mcp.dark_moon_bridge as bridge

    assert bridge._extract_text([]) == ""
    assert bridge._extract_text(None) == ""


def test_register_dark_moon_tools_uses_fallback_when_asyncio_run_fails(monkeypatch):
    """register_dark_moon_tools uses fallback list if asyncio.run raises RuntimeError."""
    import app.mcp.dark_moon_bridge as bridge

    monkeypatch.setenv("DARK_MOON_ENABLED", "true")
    bridge.DARK_MOON_ENABLED = True

    captured_names: list[str] = []

    def fake_register(name, fn, schema, description, scope):
        captured_names.append(name)

    with patch("asyncio.run", side_effect=RuntimeError("event loop running")):
        with patch("app.mcp.registry.register_tool", side_effect=fake_register):
            bridge.registered_dm_tools.clear()
            bridge.register_dark_moon_tools()

    # Should have fallen back to hardcoded tools
    assert len(captured_names) == len(bridge._FALLBACK_TOOLS)
    assert all(n.startswith("dm_") for n in captured_names)
