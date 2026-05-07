"""Tests for the 3-layer Playwright fetcher (app/fetcher.py)."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------

class TestPolicyHelpers:
    def setup_method(self):
        import app.fetcher as fetcher
        fetcher.reload_policies()

    def test_nvd_not_browser(self):
        from app.fetcher import _browser_allowed_for_url
        # NVD is configured use_browser: false
        assert _browser_allowed_for_url("https://services.nvd.nist.gov/rest/json/cves/2.0") is False

    def test_threatfox_browser(self):
        from app.fetcher import _browser_allowed_for_url
        assert _browser_allowed_for_url("https://threatfox.abuse.ch/api/v1/") is True

    def test_urlhaus_browser(self):
        from app.fetcher import _browser_allowed_for_url
        assert _browser_allowed_for_url("https://urlhaus.abuse.ch/downloads/") is True

    def test_unknown_domain_no_browser(self):
        from app.fetcher import _browser_allowed_for_url
        assert _browser_allowed_for_url("https://random-site.example.com/page") is False

    def test_private_ip_denied(self):
        from app.fetcher import _is_denied
        assert _is_denied("http://192.168.1.1/admin") is True

    def test_localhost_denied(self):
        from app.fetcher import _is_denied
        assert _is_denied("http://localhost/api") is True

    def test_public_url_not_denied(self):
        from app.fetcher import _is_denied
        assert _is_denied("https://services.nvd.nist.gov/something") is False


# ---------------------------------------------------------------------------
# CAPTCHA detection
# ---------------------------------------------------------------------------

class TestCaptchaDetection:
    def test_cloudflare_just_a_moment(self):
        from app.fetcher import _detect_captcha
        html = "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
        assert _detect_captcha(html) is True

    def test_cloudflare_attention_required(self):
        from app.fetcher import _detect_captcha
        html = "<html><head><title>Attention Required! | Cloudflare</title></head></html>"
        assert _detect_captcha(html) is True

    def test_recaptcha_body(self):
        from app.fetcher import _detect_captcha
        html = '<html><body><script src="https://www.recaptcha.net/recaptcha/api.js"></script></body></html>'
        assert _detect_captcha(html) is True

    def test_hcaptcha_body(self):
        from app.fetcher import _detect_captcha
        html = '<html><body><div class="h-captcha" data-sitekey="xxx"></div><script src="https://hcaptcha.com/captcha/api.js"></script></body></html>'
        assert _detect_captcha(html) is True

    def test_cloudflare_challenge_form(self):
        from app.fetcher import _detect_captcha
        html = '<form id="challenge-form" action="/cdn-cgi/challenge-platform/h/b/flow/ov1"></form>'
        assert _detect_captcha(html) is True

    def test_normal_page_not_captcha(self):
        from app.fetcher import _detect_captcha
        html = "<html><head><title>CVE-2024-1234 - NVD</title></head><body>Details here</body></html>"
        assert _detect_captcha(html) is False

    def test_empty_html_not_captcha(self):
        from app.fetcher import _detect_captcha
        assert _detect_captcha("") is False

    def test_access_denied_title(self):
        from app.fetcher import _detect_captcha
        html = "<html><head><title>Access Denied</title></head><body>You are blocked</body></html>"
        assert _detect_captcha(html) is True


# ---------------------------------------------------------------------------
# FetchResult dataclass
# ---------------------------------------------------------------------------

class TestFetchResult:
    def test_defaults(self):
        from app.fetcher import FetchResult
        r = FetchResult(url="https://example.com", ok=True)
        assert r.status_code == 0
        assert r.text == ""
        assert r.used_browser is False
        assert r.captcha_detected is False
        assert r.error is None

    def test_content_property(self):
        from app.fetcher import FetchResult
        r = FetchResult(url="https://example.com", ok=True, text="hello")
        assert r.content == b"hello"


# ---------------------------------------------------------------------------
# fetch() — Layer 1: PLAYWRIGHT_ENABLED=False
# ---------------------------------------------------------------------------

class TestFetchHttpxPath:
    @pytest.mark.asyncio
    async def test_fetch_uses_httpx_when_playwright_disabled(self):
        """When PLAYWRIGHT_ENABLED=False, httpx is always used even for browser-policy URLs."""
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        mock_result = FetchResult(url="https://threatfox.abuse.ch/api/", ok=True, status_code=200, text="OK")
        with (
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", False),
            patch("app.fetcher._fetch_httpx", AsyncMock(return_value=mock_result)) as mock_http,
        ):
            result = await fetcher.fetch("https://threatfox.abuse.ch/api/")
            mock_http.assert_awaited_once()
            assert result.used_browser is False

    @pytest.mark.asyncio
    async def test_fetch_denied_url(self):
        from app.fetcher import fetch, FetchResult
        result = await fetch("http://192.168.1.1/admin")
        assert result.ok is False
        assert "Denied" in (result.error or "")

    @pytest.mark.asyncio
    async def test_fetch_httpx_success(self):
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        mock_result = FetchResult(url="https://nvd.test/", ok=True, status_code=200, text="<html>NVD</html>")
        with (
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", False),
            patch("app.fetcher._fetch_httpx", AsyncMock(return_value=mock_result)),
        ):
            result = await fetcher.fetch("https://nvd.test/")
            assert result.ok is True
            assert result.text == "<html>NVD</html>"


# ---------------------------------------------------------------------------
# fetch() — Layer 2/3: PLAYWRIGHT_ENABLED=True, browser path
# ---------------------------------------------------------------------------

class TestFetchBrowserPath:
    @pytest.mark.asyncio
    async def test_browser_path_used_for_allowlisted_domain(self):
        """When enabled + policy has use_browser:true, _fetch_playwright is called."""
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        mock_result = FetchResult(
            url="https://threatfox.abuse.ch/api/",
            ok=True,
            status_code=200,
            text="<html><title>ThreatFox</title></html>",
            used_browser=True,
        )
        with (
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", True),
            patch("app.fetcher._fetch_playwright", AsyncMock(return_value=mock_result)) as mock_browser,
        ):
            fetcher.reload_policies()
            result = await fetcher.fetch("https://threatfox.abuse.ch/api/")
            mock_browser.assert_awaited_once()
            assert result.used_browser is True

    @pytest.mark.asyncio
    async def test_captcha_page_returns_captcha_detected(self):
        """CAPTCHA response from browser returns captcha_detected=True, ok=False."""
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        captcha_result = FetchResult(
            url="https://threatfox.abuse.ch/api/",
            ok=False,
            status_code=200,
            text='<html><head><title>Just a moment...</title></head></html>',
            used_browser=True,
            captcha_detected=True,
            error="CAPTCHA/bot-challenge page detected — aborting",
        )
        with (
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", True),
            patch("app.fetcher._fetch_playwright", AsyncMock(return_value=captcha_result)),
        ):
            fetcher.reload_policies()
            result = await fetcher.fetch("https://threatfox.abuse.ch/api/")
            assert result.captcha_detected is True
            assert result.ok is False

    @pytest.mark.asyncio
    async def test_browser_failure_falls_back_to_httpx(self):
        """If Playwright fails (not CAPTCHA), fallback to httpx."""
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        browser_fail = FetchResult(
            url="https://threatfox.abuse.ch/api/",
            ok=False,
            used_browser=True,
            error="Browser launch failed",
        )
        httpx_ok = FetchResult(
            url="https://threatfox.abuse.ch/api/",
            ok=True,
            status_code=200,
            text="data",
            used_browser=False,
        )
        with (
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", True),
            patch("app.fetcher._fetch_playwright", AsyncMock(return_value=browser_fail)),
            patch("app.fetcher._fetch_httpx", AsyncMock(return_value=httpx_ok)) as mock_http,
        ):
            fetcher.reload_policies()
            result = await fetcher.fetch("https://threatfox.abuse.ch/api/")
            # Should fall back to httpx and return its result
            mock_http.assert_awaited_once()
            assert result.ok is True

    @pytest.mark.asyncio
    async def test_force_browser_bypasses_policy(self):
        """force_browser=True uses browser even if policy doesn't have use_browser."""
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        mock_result = FetchResult(
            url="https://services.nvd.nist.gov/data",
            ok=True,
            status_code=200,
            text="html",
            used_browser=True,
        )
        with (
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", True),
            patch("app.fetcher._fetch_playwright", AsyncMock(return_value=mock_result)) as mock_browser,
        ):
            fetcher.reload_policies()
            result = await fetcher.fetch("https://services.nvd.nist.gov/data", force_browser=True)
            mock_browser.assert_awaited_once()


# ---------------------------------------------------------------------------
# fetch_many
# ---------------------------------------------------------------------------

class TestFetchMany:
    @pytest.mark.asyncio
    async def test_fetch_many_returns_list(self):
        import app.fetcher as fetcher
        from app.fetcher import FetchResult

        urls = [f"https://example.com/{i}" for i in range(3)]
        results = [
            FetchResult(url=u, ok=True, status_code=200, text="ok")
            for u in urls
        ]

        async def mock_fetch(url, **kwargs):
            for r in results:
                if r.url == url:
                    return r
            return FetchResult(url=url, ok=False)

        with patch("app.fetcher.fetch", side_effect=mock_fetch):
            out = await fetcher.fetch_many(urls)
            assert len(out) == 3
            assert all(r.ok for r in out)
