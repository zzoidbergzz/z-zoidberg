"""Tests for the urlscan submit-and-rescan flow."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from app.enrichment import budget
from app.enrichment.providers import urlscan as urlscan_mod
from app.enrichment.providers.urlscan import UrlscanProvider


def _patched_client(handler):
    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_cls(*args, **kwargs)

    return patch("app.enrichment.providers.urlscan.httpx.AsyncClient", side_effect=factory)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    budget._reset_counters_for_tests()
    # Make polling tests fast
    monkeypatch.setattr(urlscan_mod, "_RESCAN_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(urlscan_mod, "_RESCAN_POLL_DEADLINE", 1.0)
    monkeypatch.setattr(urlscan_mod, "_RESCAN_OVERALL_TIMEOUT", 5.0)
    yield


def _search_response(ip="1.1.1.1", domain="example.com", malicious=False, score=0):
    return {
        "total": 1,
        "results": [
            {
                "task": {"time": "2025-01-01T00:00:00Z", "url": "https://example.com/"},
                "page": {"domain": domain, "ip": ip, "country": "US", "server": "x"},
                "verdicts": {"overall": {"malicious": malicious, "score": score}},
                "result": "https://urlscan.io/result/old/",
            }
        ],
    }


def _result_payload(ip="2.2.2.2", domain="example.com", malicious=True, score=80, ips=None, countries=None):
    return {
        "verdicts": {"overall": {"malicious": malicious, "score": score}},
        "page": {"domain": domain, "ip": ip, "country": "US"},
        "task": {
            "screenshotURL": "https://urlscan.io/screenshots/uuid.png",
            "reportURL": "https://urlscan.io/result/uuid/",
        },
        "lists": {
            "ips": ips if ips is not None else ["2.2.2.2", "3.3.3.3"],
            "countries": countries if countries is not None else ["US", "DE"],
        },
    }


@pytest.mark.asyncio
async def test_rescan_happy_path():
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.method == "GET" and "search" in str(request.url):
            return httpx.Response(200, json=_search_response())
        if request.method == "POST" and "/scan/" in str(request.url):
            assert request.headers.get("API-Key") == "user-key"
            assert b'"visibility":"unlisted"' in request.content
            return httpx.Response(200, json={"uuid": "abc-uuid", "api": "x"})
        if request.method == "GET" and "/result/abc-uuid/" in str(request.url):
            return httpx.Response(200, json=_result_payload())
        return httpx.Response(500)

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="user-key")
        out = await prov.enrich("url", "https://example.com/")

    assert "rescan" in out
    rescan = out["rescan"]
    assert rescan["scan_id"] == "abc-uuid"
    assert rescan["errors"] == []
    assert rescan["before"]["page_ip"] == "1.1.1.1"
    assert rescan["after"]["page_ip"] == "2.2.2.2"
    assert rescan["delta"]["malicious_changed"] is True
    assert rescan["delta"]["score_diff"] == 80
    assert "2.2.2.2" in rescan["delta"]["new_ips"]
    assert "3.3.3.3" in rescan["delta"]["new_ips"]
    # original key shape preserved
    assert out["total_results"] == 1
    assert "results" in out


@pytest.mark.asyncio
async def test_rescan_polls_through_404_then_200():
    state = {"polls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "search" in str(request.url):
            return httpx.Response(200, json=_search_response())
        if request.method == "POST":
            return httpx.Response(200, json={"uuid": "u1"})
        if request.method == "GET" and "/result/u1/" in str(request.url):
            state["polls"] += 1
            if state["polls"] < 3:
                return httpx.Response(404, json={"status": 404})
            return httpx.Response(200, json=_result_payload())
        return httpx.Response(500)

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert state["polls"] == 3
    assert out["rescan"]["errors"] == []
    assert out["rescan"]["after"]["malicious"] is True


@pytest.mark.asyncio
async def test_rescan_overall_timeout(monkeypatch):
    monkeypatch.setattr(urlscan_mod, "_RESCAN_OVERALL_TIMEOUT", 0.05)
    monkeypatch.setattr(urlscan_mod, "_RESCAN_POLL_INTERVAL", 0.5)
    monkeypatch.setattr(urlscan_mod, "_RESCAN_POLL_DEADLINE", 5.0)

    async def slow_handler(request):
        if request.method == "GET" and "search" in str(request.url):
            return httpx.Response(200, json=_search_response())
        if request.method == "POST":
            await asyncio.sleep(1.0)
            return httpx.Response(200, json={"uuid": "x"})
        return httpx.Response(404)

    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(slow_handler)
        return real_cls(*args, **kwargs)

    with patch("app.enrichment.providers.urlscan.httpx.AsyncClient", side_effect=factory):
        prov = UrlscanProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert "rescan" in out
    assert out["rescan"]["errors"] == ["timeout_after_0s"]


@pytest.mark.asyncio
async def test_rescan_budget_exhausted(monkeypatch):
    monkeypatch.setattr("app.config.settings.URLSCAN_SUBMIT_DAILY_BUDGET", 0)

    def handler(request):
        return httpx.Response(200, json=_search_response())

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert out["rescan"] == {"skipped": "budget_exhausted"}


@pytest.mark.asyncio
async def test_ip_kind_skips_submit():
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(str(request.url))
        return httpx.Response(200, json=_search_response())

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="k")
        out = await prov.enrich("ip_address", "1.2.3.4")

    assert posts == []
    assert "rescan" not in out


@pytest.mark.asyncio
async def test_byok_key_used_over_settings(monkeypatch):
    monkeypatch.setattr("app.config.settings.URLSCAN_API_KEY", "settings-key")
    seen_keys: list[str] = []

    def handler(request):
        seen_keys.append(request.headers.get("API-Key", ""))
        if request.method == "GET" and "search" in str(request.url):
            return httpx.Response(200, json=_search_response())
        if request.method == "POST":
            return httpx.Response(200, json={"uuid": "u"})
        if request.method == "GET" and "/result/u/" in str(request.url):
            return httpx.Response(200, json=_result_payload())
        return httpx.Response(500)

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="byok-key")
        await prov.enrich("url", "https://example.com/")

    assert all(k == "byok-key" for k in seen_keys), seen_keys
    assert "settings-key" not in seen_keys


@pytest.mark.asyncio
async def test_rescan_errors_do_not_raise():
    def handler(request):
        if request.method == "GET" and "search" in str(request.url):
            return httpx.Response(200, json=_search_response())
        if request.method == "POST":
            return httpx.Response(500, text="boom")
        return httpx.Response(500)

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert "rescan" in out
    assert out["rescan"]["errors"] == ["submit_status_500"]
    # backwards-compat: original keys still present
    assert "results" in out and "total_results" in out


@pytest.mark.asyncio
async def test_rescan_disabled_via_flag():
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(1)
        return httpx.Response(200, json=_search_response())

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="k", enable_rescan=False)
        out = await prov.enrich("url", "https://example.com/")

    assert posts == []
    assert "rescan" not in out


@pytest.mark.asyncio
async def test_rescan_disabled_via_settings(monkeypatch):
    monkeypatch.setattr("app.config.settings.URLSCAN_RESCAN_ENABLED", False)
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(1)
        return httpx.Response(200, json=_search_response())

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert posts == []
    assert "rescan" not in out
