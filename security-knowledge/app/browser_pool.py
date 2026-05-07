"""Persistent Playwright browser pool.

Spawning a full Chromium process per HTTP fetch adds ~2 s of cold-start
overhead.  This module maintains a small pool of reusable ``BrowserContext``
objects so the browser process is shared across requests.

Usage (manual)::

    from app.browser_pool import browser_pool

    async with browser_pool.acquire() as page:
        response = await page.goto(url)
        html = await page.content()

FastAPI lifespan integration (in app/main.py)::

    from app.browser_pool import browser_pool

    @asynccontextmanager
    async def lifespan(app):
        await browser_pool.start()
        yield
        await browser_pool.stop()

The pool is a no-op (does nothing / raises) when ``PLAYWRIGHT_ENABLED=False``.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class BrowserPool:
    """A pool of Playwright BrowserContext objects backed by a single Chromium process.

    The pool lazily starts the browser on first use (or on explicit ``start()``
    call) and tears it down on ``stop()``.  Contexts are checked out via
    ``acquire()`` and returned to the pool automatically.  If all contexts are
    checked out, the caller waits until one is returned.

    Thread safety: asyncio only — do not use from threads.
    """

    def __init__(self, pool_size: int = 3) -> None:
        self._pool_size = pool_size
        self._pw = None          # playwright instance
        self._browser = None     # Browser (single Chromium process)
        self._contexts: asyncio.Queue = asyncio.Queue()
        self._started = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch the Chromium browser and fill the context pool."""
        if not settings.PLAYWRIGHT_ENABLED:
            logger.info("browser_pool_disabled", reason="PLAYWRIGHT_ENABLED=false")
            return

        async with self._lock:
            if self._started:
                return
            try:
                from playwright.async_api import async_playwright

                self._pw = await async_playwright().start()
                self._browser = await self._pw.chromium.launch(headless=True)

                for _ in range(self._pool_size):
                    ctx = await self._browser.new_context(
                        user_agent=(
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                        ),
                        java_script_enabled=True,
                        ignore_https_errors=False,
                    )
                    await self._contexts.put(ctx)

                self._started = True
                logger.info("browser_pool_started", pool_size=self._pool_size)
            except Exception as exc:
                logger.error("browser_pool_start_failed", error=str(exc))
                # Ensure clean state on failure
                await self._teardown()

    async def stop(self) -> None:
        """Close all contexts and shut down the browser."""
        async with self._lock:
            await self._teardown()

    async def _teardown(self) -> None:
        # Drain remaining contexts
        while not self._contexts.empty():
            try:
                ctx = self._contexts.get_nowait()
                await ctx.close()
            except Exception:
                pass

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._pw:
            try:
                await self._pw.stop()
            except Exception:
                pass
            self._pw = None

        self._started = False
        logger.info("browser_pool_stopped")

    # ------------------------------------------------------------------
    # Pool acquire / release
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def acquire(self, timeout: float = 30.0) -> AsyncIterator:
        """Yield a Playwright Page, returning the context to the pool afterwards.

        Creates a new page per request (cheap) but reuses the underlying
        BrowserContext (expensive to create).  The page is closed on exit.
        """
        if not self._started:
            # Lazy start (first use before explicit start() call)
            await self.start()

        if not self._started:
            raise RuntimeError(
                "Browser pool is not available. "
                "Set PLAYWRIGHT_ENABLED=true and ensure playwright browsers are installed."
            )

        try:
            ctx = await asyncio.wait_for(self._contexts.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Browser pool exhausted: no context available within {timeout}s. "
                f"Consider increasing pool_size (current: {self._pool_size})."
            )

        page = None
        try:
            page = await ctx.new_page()
            logger.debug("browser_context_acquired", pool_remaining=self._contexts.qsize())
            yield page
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            # Return context to pool (or replace with fresh one if something went wrong)
            try:
                await self._contexts.put(ctx)
            except Exception:
                # Context may be broken; replace with a fresh one
                if self._browser:
                    try:
                        new_ctx = await self._browser.new_context()
                        await self._contexts.put(new_ctx)
                    except Exception:
                        pass
            logger.debug("browser_context_released", pool_remaining=self._contexts.qsize())

    @property
    def is_available(self) -> bool:
        return self._started and settings.PLAYWRIGHT_ENABLED


# Module-level singleton — import and use directly
browser_pool = BrowserPool(pool_size=3)
