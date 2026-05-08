"""Tests for the Chrome 147 default User-Agent and Client Hints."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_default_user_agent_is_chrome_147():
    from app import fetcher

    captured: dict = {}

    class _Resp:
        is_success = True
        status_code = 200
        text = "<html></html>"
        headers = {"Content-Type": "text/html"}

    class _Client:
        def __init__(self, *args, **kwargs):
            captured["headers"] = kwargs.get("headers", {})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            return _Resp()

    with patch("httpx.AsyncClient", _Client):
        await fetcher._fetch_httpx("https://example.com")

    headers = captured["headers"]
    assert "Chrome/147" in headers["User-Agent"]
    assert "X11; Linux x86_64" in headers["User-Agent"]
    assert headers["Sec-Ch-Ua-Mobile"] == "?0"
    assert headers["Sec-Ch-Ua-Platform"] == '"Linux"'
    assert "Chromium" in headers["Sec-Ch-Ua"]
    assert "147" in headers["Sec-Ch-Ua"]
    assert headers["Accept-Language"] == "en-US,en;q=0.9"
    assert "gzip" in headers["Accept-Encoding"]


@pytest.mark.asyncio
async def test_caller_user_agent_overrides_default():
    from app import fetcher

    captured: dict = {}

    class _Resp:
        is_success = True
        status_code = 200
        text = ""
        headers = {}

    class _Client:
        def __init__(self, *args, **kwargs):
            captured["headers"] = kwargs.get("headers", {})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            return _Resp()

    with patch("httpx.AsyncClient", _Client):
        await fetcher._fetch_httpx(
            "https://example.com", headers={"User-Agent": "MyCustomBot/2.0"}
        )

    assert captured["headers"]["User-Agent"] == "MyCustomBot/2.0"
