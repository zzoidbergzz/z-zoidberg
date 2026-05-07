"""Tests for rate-limit enforcement in app/fetcher.py."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestParseRateLimit:
    def test_per_day(self):
        from app.fetcher import _parse_rate_limit
        count, secs = _parse_rate_limit("100/day")
        assert count == 100
        assert secs == 86400

    def test_per_hour(self):
        from app.fetcher import _parse_rate_limit
        count, secs = _parse_rate_limit("1000/hour")
        assert count == 1000
        assert secs == 3600

    def test_per_minute(self):
        from app.fetcher import _parse_rate_limit
        count, secs = _parse_rate_limit("60/minute")
        assert count == 60
        assert secs == 60

    def test_invalid_returns_zeros(self):
        from app.fetcher import _parse_rate_limit
        assert _parse_rate_limit("badvalue") == (0, 0)
        assert _parse_rate_limit("") == (0, 0)

    def test_with_spaces(self):
        from app.fetcher import _parse_rate_limit
        count, secs = _parse_rate_limit(" 500/hour ")
        assert count == 500
        assert secs == 3600


class TestEnforceRateLimit:
    @pytest.mark.asyncio
    async def test_no_policy_allows(self):
        from app.fetcher import _enforce_rate_limit
        result = await _enforce_rate_limit("https://unknown-domain-xyz.example/path")
        assert result is True

    @pytest.mark.asyncio
    async def test_policy_no_rate_limit_allows(self):
        from app.fetcher import _enforce_rate_limit
        result = await _enforce_rate_limit("https://www.cisa.gov/known-exploited-vulnerabilities")
        assert result is True

    @pytest.mark.asyncio
    async def test_redis_unavailable_fails_open(self):
        """When Redis is down, fail open (allow the request)."""
        from app.fetcher import _enforce_rate_limit

        with patch("redis.asyncio.from_url", side_effect=Exception("connection refused")):
            result = await _enforce_rate_limit("https://services.nvd.nist.gov/data")
            assert result is True

    @pytest.mark.asyncio
    async def test_under_limit_allowed(self):
        """First request under the limit should be allowed."""
        import app.fetcher as fetcher

        mock_redis = AsyncMock()
        mock_redis.__aenter__ = AsyncMock(return_value=mock_redis)
        mock_redis.__aexit__ = AsyncMock(return_value=None)
        mock_redis.incr = AsyncMock(return_value=1)   # first request
        mock_redis.expire = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            fetcher.reload_policies()
            result = await fetcher._enforce_rate_limit("https://services.nvd.nist.gov/rest/json/cves/2.0")
            assert result is True

    @pytest.mark.asyncio
    async def test_over_limit_denied(self):
        """When count exceeds limit, request should be denied."""
        import app.fetcher as fetcher

        mock_redis = AsyncMock()
        mock_redis.__aenter__ = AsyncMock(return_value=mock_redis)
        mock_redis.__aexit__ = AsyncMock(return_value=None)
        mock_redis.incr = AsyncMock(return_value=101)  # exceeded 100/day
        mock_redis.expire = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            fetcher.reload_policies()
            result = await fetcher._enforce_rate_limit("https://services.nvd.nist.gov/rest/json/cves/2.0")
            assert result is False

    @pytest.mark.asyncio
    async def test_rate_limited_fetch_returns_429(self):
        """fetch() returns a 429 FetchResult when rate limit is exceeded."""
        import app.fetcher as fetcher

        mock_redis = AsyncMock()
        mock_redis.__aenter__ = AsyncMock(return_value=mock_redis)
        mock_redis.__aexit__ = AsyncMock(return_value=None)
        mock_redis.incr = AsyncMock(return_value=999)
        mock_redis.expire = AsyncMock()

        with (
            patch("redis.asyncio.from_url", return_value=mock_redis),
            patch.object(fetcher.settings, "PLAYWRIGHT_ENABLED", False),
        ):
            fetcher.reload_policies()
            result = await fetcher.fetch("https://services.nvd.nist.gov/data")
            assert result.ok is False
            assert result.status_code == 429
            assert "Rate limit" in (result.error or "")
