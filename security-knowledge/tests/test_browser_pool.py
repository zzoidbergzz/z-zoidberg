"""Tests for the Playwright BrowserPool (app/browser_pool.py)."""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestBrowserPoolDisabled:
    @pytest.mark.asyncio
    async def test_start_noop_when_disabled(self):
        from app.browser_pool import BrowserPool
        pool = BrowserPool(pool_size=2)
        with patch("app.browser_pool.settings") as mock_settings:
            mock_settings.PLAYWRIGHT_ENABLED = False
            await pool.start()
            assert pool.is_available is False

    @pytest.mark.asyncio
    async def test_acquire_raises_when_disabled(self):
        from app.browser_pool import BrowserPool
        pool = BrowserPool(pool_size=2)
        with patch("app.browser_pool.settings") as mock_settings:
            mock_settings.PLAYWRIGHT_ENABLED = False
            with pytest.raises(RuntimeError, match="not available"):
                async with pool.acquire():
                    pass

    @pytest.mark.asyncio
    async def test_stop_noop_when_never_started(self):
        from app.browser_pool import BrowserPool
        pool = BrowserPool(pool_size=1)
        await pool.stop()  # should not raise


class TestBrowserPoolEnabled:
    @pytest.mark.asyncio
    async def test_is_available_false_before_start(self):
        from app.browser_pool import BrowserPool
        pool = BrowserPool()
        with patch("app.browser_pool.settings") as s:
            s.PLAYWRIGHT_ENABLED = True
            # Not started yet
            assert pool.is_available is False

    @pytest.mark.asyncio
    async def test_pool_singleton_exists(self):
        """Module-level singleton should exist."""
        from app.browser_pool import browser_pool, BrowserPool
        assert isinstance(browser_pool, BrowserPool)

    @pytest.mark.asyncio
    async def test_start_sets_started_flag(self):
        """Pool _started flag is set after successful start."""
        from app.browser_pool import BrowserPool

        mock_page = AsyncMock()
        mock_page.close = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.new_page = AsyncMock(return_value=mock_page)
        mock_ctx.close = AsyncMock()

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_ctx)
        mock_browser.close = AsyncMock()

        mock_chromium = AsyncMock()
        mock_chromium.launch = AsyncMock(return_value=mock_browser)

        mock_pw_obj = AsyncMock()
        mock_pw_obj.chromium = mock_chromium
        mock_pw_obj.stop = AsyncMock()

        pool = BrowserPool(pool_size=2)
        with (
            patch("app.browser_pool.settings") as mock_settings,
            patch("playwright.async_api.async_playwright") as mock_apw,
        ):
            mock_settings.PLAYWRIGHT_ENABLED = True
            mock_apw.return_value.start = AsyncMock(return_value=mock_pw_obj)

            await pool.start()
            assert pool._started is True
            assert not pool._contexts.empty()

    @pytest.mark.asyncio
    async def test_acquire_returns_page(self):
        """Acquire yields a page from the pool."""
        from app.browser_pool import BrowserPool

        mock_page = AsyncMock()
        mock_page.close = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.new_page = AsyncMock(return_value=mock_page)
        mock_ctx.close = AsyncMock()

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_ctx)
        mock_browser.close = AsyncMock()

        mock_chromium = AsyncMock()
        mock_chromium.launch = AsyncMock(return_value=mock_browser)

        mock_pw_obj = AsyncMock()
        mock_pw_obj.chromium = mock_chromium
        mock_pw_obj.stop = AsyncMock()

        pool = BrowserPool(pool_size=1)
        with (
            patch("app.browser_pool.settings") as mock_settings,
            patch("playwright.async_api.async_playwright") as mock_apw,
        ):
            mock_settings.PLAYWRIGHT_ENABLED = True
            mock_apw.return_value.start = AsyncMock(return_value=mock_pw_obj)

            await pool.start()

            received_page = None
            async with pool.acquire() as page:
                received_page = page

            assert received_page is mock_page
            mock_page.close.assert_awaited()

    @pytest.mark.asyncio
    async def test_context_returned_to_pool_after_use(self):
        """Context is returned to the queue after acquire exits."""
        from app.browser_pool import BrowserPool

        mock_page = AsyncMock()
        mock_page.close = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.new_page = AsyncMock(return_value=mock_page)
        mock_ctx.close = AsyncMock()

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_ctx)
        mock_browser.close = AsyncMock()

        mock_chromium = AsyncMock()
        mock_chromium.launch = AsyncMock(return_value=mock_browser)

        mock_pw_obj = AsyncMock()
        mock_pw_obj.chromium = mock_chromium
        mock_pw_obj.stop = AsyncMock()

        pool = BrowserPool(pool_size=1)
        with (
            patch("app.browser_pool.settings") as mock_settings,
            patch("playwright.async_api.async_playwright") as mock_apw,
        ):
            mock_settings.PLAYWRIGHT_ENABLED = True
            mock_apw.return_value.start = AsyncMock(return_value=mock_pw_obj)

            await pool.start()
            assert pool._contexts.qsize() == 1

            async with pool.acquire():
                assert pool._contexts.qsize() == 0  # checked out

            assert pool._contexts.qsize() == 1  # returned


class TestBrowserPoolSSEEndpoint:
    """Ensure SSE endpoint is registered correctly."""

    def test_sse_endpoint_in_enrich_router(self):
        from app.routers.enrich import router
        paths = [r.path for r in router.routes]
        assert "/enrich/{entity_kind}/{entity_value}/stream" in paths

    def test_sse_endpoint_is_get(self):
        from app.routers.enrich import router
        for r in router.routes:
            if r.path == "/{entity_kind}/{entity_value}/stream":
                assert "GET" in r.methods
                break

    def test_export_router_registered(self):
        from app.routers.export import router
        paths = [r.path for r in router.routes]
        assert "/export/stix" in paths
