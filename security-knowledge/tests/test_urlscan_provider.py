"""Tests for the urlscan.io enrichment provider."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from app.enrichment.providers.urlscan import UrlscanProvider


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def _patched_client(handler):
    """Patch httpx.AsyncClient so the provider uses our MockTransport."""
    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = _mock_transport(handler)
        return real_cls(*args, **kwargs)

    return patch("app.enrichment.providers.urlscan.httpx.AsyncClient", side_effect=factory)


@pytest.mark.asyncio
async def test_url_search_success():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["api_key_header"] = request.headers.get("API-Key")
        return httpx.Response(
            200,
            json={
                "total": 2,
                "results": [
                    {
                        "task": {"time": "2025-01-02T03:04:05Z", "url": "https://www.google.com/"},
                        "page": {
                            "domain": "www.google.com",
                            "ip": "142.250.74.4",
                            "country": "US",
                            "server": "gws",
                        },
                        "verdicts": {"overall": {"malicious": False, "score": 0}},
                        "screenshot": "https://urlscan.io/screenshots/abc.png",
                        "result": "https://urlscan.io/result/abc/",
                    },
                    {
                        "task": {"time": "2025-01-01T00:00:00Z", "url": "https://www.google.com/"},
                        "page": {
                            "domain": "www.google.com",
                            "ip": "142.250.74.5",
                            "country": "US",
                            "server": "gws",
                        },
                        "verdicts": {"overall": {"malicious": False, "score": 0}},
                        "screenshot": "https://urlscan.io/screenshots/def.png",
                        "result": "https://urlscan.io/result/def/",
                    },
                ],
            },
        )

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="test-key")
        out = await prov.enrich("url", "https://www.google.com/")

    assert captured["api_key_header"] == "test-key"
    assert "page.url" in captured["url"]
    assert out["total_results"] == 2
    assert len(out["results"]) == 2
    assert out["unique_ips"] == ["142.250.74.4", "142.250.74.5"]
    assert out["unique_domains"] == ["www.google.com"]
    assert out["any_malicious"] is False
    assert out["latest_scan_time"] == "2025-01-02T03:04:05Z"
    assert out["urlscan_search_link"].startswith("https://urlscan.io/search/#")


@pytest.mark.asyncio
async def test_ip_search_success():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "total": 1,
                "results": [
                    {
                        "task": {"time": "2025-02-02T00:00:00Z", "url": "http://example.com/"},
                        "page": {"domain": "example.com", "ip": "8.8.8.8", "country": "US", "server": "nginx"},
                        "verdicts": {"overall": {"malicious": True, "score": 100}},
                        "screenshot": "https://urlscan.io/screenshots/x.png",
                        "result": "https://urlscan.io/result/x/",
                    }
                ],
            },
        )

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="test-key")
        out = await prov.enrich("ip_address", "8.8.8.8")

    assert "page.ip" in captured["url"]
    assert out["any_malicious"] is True
    assert out["unique_ips"] == ["8.8.8.8"]
    assert out["results"][0]["score"] == 100


@pytest.mark.asyncio
async def test_empty_results_falls_back_to_domain_for_url():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        # First call (page.url:"...") returns empty; fallback (domain:foo) returns one
        if "page.url" in str(request.url):
            return httpx.Response(200, json={"total": 0, "results": []})
        return httpx.Response(
            200,
            json={
                "total": 1,
                "results": [
                    {
                        "task": {"time": "2025-03-03T00:00:00Z", "url": "https://foo.example/"},
                        "page": {"domain": "foo.example", "ip": "1.2.3.4", "country": "US", "server": "x"},
                        "verdicts": {"overall": {"malicious": False, "score": 0}},
                    }
                ],
            },
        )

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="test-key")
        out = await prov.enrich("url", "https://foo.example/never-seen")

    assert len(calls) == 2
    assert "domain%3Afoo.example" in calls[1] or "domain:foo.example" in calls[1]
    assert out["total_results"] == 1


@pytest.mark.asyncio
async def test_empty_results_no_fallback_when_no_match():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total": 0, "results": []})

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="test-key")
        out = await prov.enrich("ip_address", "203.0.113.99")

    assert out["total_results"] == 0
    assert out["results"] == []
    assert out["unique_ips"] == []
    assert out["any_malicious"] is False
    assert out["latest_scan_time"] is None


@pytest.mark.asyncio
async def test_rate_limited_returns_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "Rate limit exceeded"})

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="test-key")
        out = await prov.enrich("url", "https://example.com/")

    assert out == {}


@pytest.mark.asyncio
async def test_missing_api_key_short_circuits(monkeypatch):
    monkeypatch.setattr("app.enrichment.providers.urlscan.settings.URLSCAN_API_KEY", "")
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"total": 0, "results": []})

    with _patched_client(handler):
        prov = UrlscanProvider()
        out = await prov.enrich("url", "https://example.com/")

    assert out == {}
    assert called is False


@pytest.mark.asyncio
async def test_unsupported_kind_short_circuits():
    prov = UrlscanProvider(api_key="test-key")
    out = await prov.enrich("hash", "deadbeef")
    assert out == {}


def test_supports_url_and_ip_kinds():
    assert "url" in UrlscanProvider.supported_kinds
    assert "ip_address" in UrlscanProvider.supported_kinds


def test_api_key_override():
    inst = UrlscanProvider(api_key="user-supplied-key")
    assert inst.api_key == "user-supplied-key"
    assert inst.api_key_override == "user-supplied-key"
