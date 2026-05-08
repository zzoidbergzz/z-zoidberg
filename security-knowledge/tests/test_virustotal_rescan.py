"""Tests for VirusTotal submit-and-rescan flow."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from app.enrichment import budget
from app.enrichment.providers import virustotal as vt_mod
from app.enrichment.providers.virustotal import VirusTotalProvider, _vt_url_id


def _patched_client(handler):
    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_cls(*args, **kwargs)

    return patch("app.enrichment.providers.virustotal.httpx.AsyncClient", side_effect=factory)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    budget._reset_counters_for_tests()
    # Drain VT minute-rate-limiter state so 4-req cap doesn't bleed across tests
    vt_mod._req_timestamps.clear()
    monkeypatch.setattr(vt_mod, "_RESCAN_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(vt_mod, "_RESCAN_POLL_DEADLINE", 1.0)
    monkeypatch.setattr(vt_mod, "_RESCAN_OVERALL_TIMEOUT", 5.0)
    monkeypatch.setattr(vt_mod, "_VT_MAX_PER_MINUTE", 10000)
    yield


def _url_payload(stats=None, reputation=0, results=None):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": stats or {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20, "timeout": 0},
                "reputation": reputation,
                "total_votes": {"malicious": 0, "harmless": 1},
                "last_analysis_results": results or {},
                "last_analysis_date": 1700000000,
            }
        }
    }


@pytest.mark.asyncio
async def test_rescan_happy_path_with_diff():
    url = "https://example.com/"
    url_id = _vt_url_id(url)
    state = {"url_gets": 0, "analysis_gets": 0}

    def handler(request):
        path = request.url.path
        if request.method == "GET" and path.endswith(f"/urls/{url_id}"):
            state["url_gets"] += 1
            if state["url_gets"] == 1:
                # before
                return httpx.Response(200, json=_url_payload(
                    stats={"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20, "timeout": 0},
                    reputation=0,
                    results={"EngineA": {"category": "harmless"}},
                ))
            # after
            return httpx.Response(200, json=_url_payload(
                stats={"malicious": 3, "suspicious": 1, "harmless": 65, "undetected": 21, "timeout": 0},
                reputation=-5,
                results={
                    "EngineA": {"category": "malicious"},
                    "EngineB": {"category": "suspicious"},
                },
            ))
        if request.method == "POST" and path == "/api/v3/urls":
            assert request.headers.get("x-apikey") == "user-key"
            assert b"url=" in request.content
            return httpx.Response(200, json={"data": {"id": "analysis-1"}})
        if request.method == "GET" and path.endswith("/analyses/analysis-1"):
            state["analysis_gets"] += 1
            if state["analysis_gets"] < 2:
                return httpx.Response(200, json={"data": {"attributes": {"status": "queued"}}})
            return httpx.Response(200, json={"data": {"attributes": {"status": "completed"}}})
        return httpx.Response(500, json={"path": path})

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="user-key")
        out = await prov.enrich("url", url)

    assert out["resource_type"] == "urls"
    assert "rescan" in out
    rescan = out["rescan"]
    assert rescan["scan_id"] == "analysis-1"
    assert rescan["errors"] == []
    assert rescan["before"]["stats"]["malicious"] == 0
    assert rescan["after"]["stats"]["malicious"] == 3
    assert rescan["delta"]["stats_diff"]["malicious"] == 3
    assert rescan["delta"]["stats_diff"]["suspicious"] == 1
    assert rescan["delta"]["stats_diff"]["harmless"] == -5
    assert rescan["delta"]["reputation_diff"] == -5
    engines = {d["engine"] for d in rescan["delta"]["new_detections"]}
    assert "EngineA" in engines and "EngineB" in engines


@pytest.mark.asyncio
async def test_rescan_polls_until_completed():
    url = "https://example.com/"
    url_id = _vt_url_id(url)
    state = {"polls": 0}

    def handler(request):
        path = request.url.path
        if request.method == "GET" and path.endswith(f"/urls/{url_id}"):
            return httpx.Response(200, json=_url_payload())
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "an-x"}})
        if request.method == "GET" and "/analyses/" in path:
            state["polls"] += 1
            if state["polls"] < 4:
                return httpx.Response(200, json={"data": {"attributes": {"status": "queued"}}})
            return httpx.Response(200, json={"data": {"attributes": {"status": "completed"}}})
        return httpx.Response(500)

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="k")
        out = await prov.enrich("url", url)

    assert state["polls"] == 4
    assert out["rescan"]["errors"] == []


@pytest.mark.asyncio
async def test_rescan_overall_timeout(monkeypatch):
    monkeypatch.setattr(vt_mod, "_RESCAN_OVERALL_TIMEOUT", 0.05)
    monkeypatch.setattr(vt_mod, "_RESCAN_POLL_INTERVAL", 0.5)

    async def handler(request):
        path = request.url.path
        if request.method == "GET" and "/urls/" in path and "/analyses/" not in path:
            return httpx.Response(200, json=_url_payload())
        if request.method == "POST":
            await asyncio.sleep(1.0)
            return httpx.Response(200, json={"data": {"id": "x"}})
        return httpx.Response(404)

    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_cls(*args, **kwargs)

    with patch("app.enrichment.providers.virustotal.httpx.AsyncClient", side_effect=factory):
        prov = VirusTotalProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert out["rescan"]["errors"] == ["timeout_after_0s"]


@pytest.mark.asyncio
async def test_rescan_budget_exhausted(monkeypatch):
    monkeypatch.setattr("app.config.settings.VIRUSTOTAL_SUBMIT_DAILY_BUDGET", 0)

    def handler(request):
        if request.method == "GET" and "/urls/" in request.url.path:
            return httpx.Response(200, json=_url_payload())
        return httpx.Response(500)

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert out["rescan"] == {"skipped": "budget_exhausted"}


@pytest.mark.asyncio
async def test_ip_kind_skips_submit():
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(str(request.url))
        if "/ip_addresses/" in request.url.path:
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {}, "country": "US"}}})
        return httpx.Response(500)

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="k")
        out = await prov.enrich("ip_address", "1.2.3.4")

    assert posts == []
    assert "rescan" not in out
    assert out["resource_type"] == "ip_addresses"


@pytest.mark.asyncio
async def test_byok_key_used_over_settings(monkeypatch):
    monkeypatch.setattr("app.config.settings.VIRUSTOTAL_API_KEY", "settings-key")
    seen_keys: list[str] = []

    def handler(request):
        seen_keys.append(request.headers.get("x-apikey", ""))
        path = request.url.path
        if request.method == "GET" and "/urls/" in path and "/analyses/" not in path:
            return httpx.Response(200, json=_url_payload())
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "id"}})
        if request.method == "GET" and "/analyses/" in path:
            return httpx.Response(200, json={"data": {"attributes": {"status": "completed"}}})
        return httpx.Response(500)

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="byok-key")
        await prov.enrich("url", "https://example.com/")

    assert seen_keys, "no requests captured"
    assert all(k == "byok-key" for k in seen_keys), seen_keys


@pytest.mark.asyncio
async def test_rescan_errors_do_not_raise():
    def handler(request):
        path = request.url.path
        if request.method == "GET" and "/urls/" in path:
            return httpx.Response(200, json=_url_payload())
        if request.method == "POST":
            return httpx.Response(500, text="boom")
        return httpx.Response(500)

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="k")
        out = await prov.enrich("url", "https://example.com/")

    assert "rescan" in out
    assert out["rescan"]["errors"] == ["submit_status_500"]
    # backwards-compat: original keys present
    assert "malicious" in out and "vt_link" in out


@pytest.mark.asyncio
async def test_rescan_disabled_via_flag():
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(1)
        if "/urls/" in request.url.path:
            return httpx.Response(200, json=_url_payload())
        return httpx.Response(500)

    with _patched_client(handler):
        prov = VirusTotalProvider(api_key="k", enable_rescan=False)
        out = await prov.enrich("url", "https://example.com/")

    assert posts == []
    assert "rescan" not in out


def test_diff_math():
    before = {
        "stats": {"malicious": 1, "suspicious": 0, "harmless": 50, "undetected": 30, "timeout": 0},
        "reputation": 5,
        "top_detections": [{"engine": "EngineA", "category": "malicious"}],
    }
    after = {
        "stats": {"malicious": 4, "suspicious": 2, "harmless": 48, "undetected": 30, "timeout": 0},
        "reputation": -3,
        "top_detections": [
            {"engine": "EngineA", "category": "malicious"},
            {"engine": "EngineC", "category": "suspicious"},
        ],
    }
    d = VirusTotalProvider._diff(before, after)
    assert d["stats_diff"] == {"malicious": 3, "suspicious": 2, "harmless": -2, "undetected": 0, "timeout": 0}
    assert d["reputation_diff"] == -8
    assert d["new_detections"] == [{"engine": "EngineC", "category": "suspicious"}]
