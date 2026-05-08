"""3-layer HTTP fetcher with optional Playwright browser fallback.

Layer 1 — Global toggle
    If ``settings.PLAYWRIGHT_ENABLED`` is False, all requests use httpx.
    This is the default; opt in by setting PLAYWRIGHT_ENABLED=true in .env.

Layer 2 — Per-domain allowlist (source-policy.yaml)
    Each source policy entry may include ``use_browser: true``.  Only
    domains that appear in such an entry are eligible for browser fetching.
    Example policy entry::

        - name: allow-cloudflare-protected-site
          sources:
            - pattern: "https://example.com/*"
          action: allow
          use_browser: true

Layer 3 — CAPTCHA / challenge detection
    Even when browser fetching is allowed, if the returned page content
    looks like a CAPTCHA or bot challenge we abort, log the event, and
    return a ``FetchResult`` with ``captcha_detected=True`` rather than
    silently returning junk HTML.

Usage::

    from app.fetcher import fetch

    result = await fetch("https://example.com/report")
    if result.ok:
        html = result.text
"""
from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog
import yaml

from app.config import settings

# ---------------------------------------------------------------------------
# Rate limiting (fixed-window token counter via Redis)
# ---------------------------------------------------------------------------

_PERIOD_SECONDS: dict[str, int] = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


def _parse_rate_limit(rate_str: str) -> tuple[int, int]:
    """Parse '100/day' → (100, 86400).  Returns (0, 0) on parse failure."""
    try:
        count_s, period = rate_str.strip().split("/", 1)
        window = _PERIOD_SECONDS.get(period.lower().rstrip("s"), 0)
        return int(count_s), window
    except Exception:
        return 0, 0


async def _check_rate_limit(url: str) -> bool:
    """Return True if the request is within the policy rate limit.

    Uses a Redis fixed-window counter.  Fails open (returns True) if Redis is
    unavailable or the policy has no rate_limit field.
    """
    policy = _get_policy_for_url.__wrapped__(url) if hasattr(_get_policy_for_url, "__wrapped__") else None
    # Inline lookup to avoid circular reference before function is defined;
    # the real call happens after _get_policy_for_url is defined below.
    return True  # placeholder — replaced after _get_policy_for_url definition


async def _enforce_rate_limit(url: str) -> bool:
    """Actual rate-limit check — called from fetch() after policy helpers are defined."""
    policy = _get_policy_for_url(url)
    if not policy:
        return True
    rate_str = policy.get("rate_limit", "")
    if not rate_str:
        return True

    max_count, window_secs = _parse_rate_limit(rate_str)
    if not max_count or not window_secs:
        return True

    window_id = int(time.time()) // window_secs
    key = f"sk:ratelimit:{policy['name']}:{window_id}"

    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        async with r:
            current = await r.incr(key)
            if current == 1:
                await r.expire(key, window_secs)
            allowed = current <= max_count
            if not allowed:
                logger.warning(
                    "fetch_rate_limited",
                    url=url,
                    policy=policy["name"],
                    count=current,
                    limit=max_count,
                    window=f"{window_secs}s",
                )
            return allowed
    except Exception as exc:
        logger.debug("rate_limit_redis_unavailable", error=str(exc))
        return True  # Fail open

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

_POLICY_PATH = Path(__file__).parent.parent / "source-policy.yaml"
_policy_cache: list[dict[str, Any]] | None = None


def _load_policies() -> list[dict[str, Any]]:
    global _policy_cache
    if _policy_cache is not None:
        return _policy_cache
    if not _POLICY_PATH.exists():
        _policy_cache = []
        return _policy_cache
    with _POLICY_PATH.open() as f:
        data = yaml.safe_load(f) or {}
    _policy_cache = data.get("policies", [])
    return _policy_cache


def reload_policies() -> None:
    """Force-reload source-policy.yaml (useful in tests / hot-reload)."""
    global _policy_cache
    _policy_cache = None


def _url_matches_pattern(url: str, pattern: str) -> bool:
    """Glob-style URL pattern matching (supports * wildcards)."""
    return fnmatch.fnmatch(url, pattern)


def _get_policy_for_url(url: str) -> dict[str, Any] | None:
    for policy in _load_policies():
        if policy.get("action") == "deny":
            for src in policy.get("sources", []):
                if _url_matches_pattern(url, src.get("pattern", "")):
                    return policy
        for src in policy.get("sources", []):
            if _url_matches_pattern(url, src.get("pattern", "")):
                return policy
    return None


def _is_denied(url: str) -> bool:
    policy = _get_policy_for_url(url)
    return policy is not None and policy.get("action") == "deny"


def _browser_allowed_for_url(url: str) -> bool:
    """Return True if source-policy.yaml has use_browser: true for this URL."""
    policy = _get_policy_for_url(url)
    return policy is not None and bool(policy.get("use_browser", False))


# ---------------------------------------------------------------------------
# CAPTCHA / challenge detection heuristics
# ---------------------------------------------------------------------------

_CAPTCHA_TITLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"just a moment", re.IGNORECASE),           # Cloudflare
    re.compile(r"ddos.?protection", re.IGNORECASE),
    re.compile(r"attention required", re.IGNORECASE),       # Cloudflare generic
    re.compile(r"access denied", re.IGNORECASE),
    re.compile(r"are you human", re.IGNORECASE),
    re.compile(r"bot.?check", re.IGNORECASE),
    re.compile(r"captcha", re.IGNORECASE),
    re.compile(r"security check", re.IGNORECASE),
    re.compile(r"ray id", re.IGNORECASE),                   # Cloudflare footer
    re.compile(r"enable javascript and cookies", re.IGNORECASE),
    re.compile(r"verify you are human", re.IGNORECASE),
]

_CAPTCHA_BODY_PATTERNS: list[re.Pattern] = [
    re.compile(r"<title>[^<]*(?:captcha|just a moment|ddos)[^<]*</title>", re.IGNORECASE),
    re.compile(r'id="challenge-form"', re.IGNORECASE),
    re.compile(r'name="cf-turnstile-response"', re.IGNORECASE),
    re.compile(r"__cf_chl_jschl_tk__", re.IGNORECASE),
    re.compile(r"window\._cf_chl_opt", re.IGNORECASE),
    re.compile(r"recaptcha\.net/recaptcha", re.IGNORECASE),
    re.compile(r"hcaptcha\.com/captcha", re.IGNORECASE),
]


def _detect_captcha(html: str) -> bool:
    """Return True if the HTML looks like a CAPTCHA / bot-challenge page."""
    # Extract title for faster matching
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""

    for pattern in _CAPTCHA_TITLE_PATTERNS:
        if pattern.search(title):
            return True

    # Body patterns (check first 8KB only to avoid scanning massive pages)
    sample = html[:8192]
    for pattern in _CAPTCHA_BODY_PATTERNS:
        if pattern.search(sample):
            return True

    return False


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    url: str
    ok: bool
    status_code: int = 0
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    used_browser: bool = False
    captcha_detected: bool = False
    error: str | None = None

    @property
    def content(self) -> bytes:
        return self.text.encode()


# ---------------------------------------------------------------------------
# httpx fetch (Layer 1 default path)
# ---------------------------------------------------------------------------

CHROME_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)

DEFAULT_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": CHROME_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="147", "Not?A_Brand";v="24", "Google Chrome";v="147"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Linux"',
}


async def _fetch_httpx(url: str, timeout: int = 30, headers: dict | None = None) -> FetchResult:
    import httpx

    # Caller-supplied headers win (case-insensitive on User-Agent).
    overrides = headers or {}
    has_ua_override = any(k.lower() == "user-agent" for k in overrides)
    merged = {**DEFAULT_BROWSER_HEADERS, **overrides}
    if has_ua_override:
        # Drop our default UA so the override (with its original casing) wins.
        merged.pop("User-Agent", None)
        merged.update(overrides)

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers=merged,
        ) as client:
            resp = await client.get(url)
            elapsed = (time.monotonic() - t0) * 1000
            return FetchResult(
                url=url,
                ok=resp.is_success,
                status_code=resp.status_code,
                text=resp.text,
                headers=dict(resp.headers),
                elapsed_ms=elapsed,
                used_browser=False,
            )
    except Exception as exc:
        elapsed = (time.monotonic() - t0) * 1000
        logger.warning("httpx_fetch_error", url=url, error=str(exc))
        return FetchResult(url=url, ok=False, elapsed_ms=elapsed, error=str(exc))


# ---------------------------------------------------------------------------
# Playwright fetch (Layer 2 browser path)
# ---------------------------------------------------------------------------

async def _fetch_playwright(url: str, timeout_ms: int | None = None) -> FetchResult:
    """Fetch a URL using the shared browser pool.

    Acquires a Page from the BrowserPool singleton (reused Chromium context),
    navigates, waits for JS rendering, then applies CAPTCHA detection.
    """
    timeout_ms = timeout_ms or settings.PLAYWRIGHT_TIMEOUT_MS
    from app.browser_pool import browser_pool

    t0 = time.monotonic()
    try:
        async with browser_pool.acquire(timeout=timeout_ms / 1000) as page:
            try:
                response = await page.goto(
                    url,
                    timeout=timeout_ms,
                    wait_until="domcontentloaded",
                )
                # Brief pause to let JS-rendered content settle
                await page.wait_for_timeout(1500)
                html = await page.content()
                status = response.status if response else 0
                resp_headers = dict(response.headers) if response else {}
            except Exception as nav_exc:
                elapsed = (time.monotonic() - t0) * 1000
                logger.warning("playwright_navigation_error", url=url, error=str(nav_exc))
                return FetchResult(
                    url=url, ok=False, elapsed_ms=elapsed, used_browser=True, error=str(nav_exc)
                )

        elapsed = (time.monotonic() - t0) * 1000

        # Layer 3 — CAPTCHA detection
        if _detect_captcha(html):
            logger.warning("captcha_detected", url=url, elapsed_ms=round(elapsed, 1))
            return FetchResult(
                url=url,
                ok=False,
                status_code=status,
                text=html,
                headers=resp_headers,
                elapsed_ms=elapsed,
                used_browser=True,
                captcha_detected=True,
                error="CAPTCHA/bot-challenge page detected — aborting",
            )

        return FetchResult(
            url=url,
            ok=200 <= status < 300,
            status_code=status,
            text=html,
            headers=resp_headers,
            elapsed_ms=elapsed,
            used_browser=True,
        )

    except RuntimeError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        logger.warning("playwright_pool_error", url=url, error=str(exc))
        return FetchResult(url=url, ok=False, elapsed_ms=elapsed, used_browser=True, error=str(exc))
    except Exception as exc:
        elapsed = (time.monotonic() - t0) * 1000
        logger.warning("playwright_fetch_error", url=url, error=str(exc))
        return FetchResult(url=url, ok=False, elapsed_ms=elapsed, used_browser=True, error=str(exc))


# ---------------------------------------------------------------------------
# Public API — 3-layer fetch
# ---------------------------------------------------------------------------

async def fetch(
    url: str,
    *,
    timeout: int = 30,
    headers: dict | None = None,
    force_browser: bool = False,
) -> FetchResult:
    """Fetch a URL using the 3-layer strategy.

    Layer 1: If PLAYWRIGHT_ENABLED=False (default), always use httpx.
    Layer 2: If the URL's policy has use_browser=True AND Playwright is
             enabled, use the browser path.
    Layer 3: After browser fetch, CAPTCHA detection aborts junk responses.

    Args:
        url: The URL to fetch.
        timeout: Seconds for httpx; milliseconds for Playwright is
                 taken from settings.PLAYWRIGHT_TIMEOUT_MS.
        headers: Extra request headers (httpx only).
        force_browser: Skip policy check and force Playwright (requires
                       PLAYWRIGHT_ENABLED=True).
    """
    if _is_denied(url):
        logger.warning("fetch_denied_by_policy", url=url)
        return FetchResult(url=url, ok=False, error="Denied by source policy")

    # Rate-limit check (Redis fixed-window counter)
    if not await _enforce_rate_limit(url):
        return FetchResult(url=url, ok=False, status_code=429, error="Rate limit exceeded per source policy")

    use_browser = (
        settings.PLAYWRIGHT_ENABLED
        and (force_browser or _browser_allowed_for_url(url))
    )

    if use_browser:
        logger.info("fetch_via_browser", url=url)
        result = await _fetch_playwright(url, timeout_ms=settings.PLAYWRIGHT_TIMEOUT_MS)

        # Fallback to httpx if browser completely failed (not CAPTCHA)
        if not result.ok and not result.captcha_detected:
            logger.info(
                "browser_fetch_failed_falling_back_to_httpx",
                url=url,
                error=result.error,
            )
            return await _fetch_httpx(url, timeout=timeout, headers=headers)

        return result

    return await _fetch_httpx(url, timeout=timeout, headers=headers)


async def fetch_many(
    urls: list[str],
    *,
    concurrency: int = 5,
    timeout: int = 30,
) -> list[FetchResult]:
    """Fetch multiple URLs with bounded concurrency."""
    import asyncio

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(url: str) -> FetchResult:
        async with semaphore:
            return await fetch(url, timeout=timeout)

    return await asyncio.gather(*[_bounded(u) for u in urls])
