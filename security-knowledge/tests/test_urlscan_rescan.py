"""Tests for the urlscan pending-scan flow."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from app.enrichment.providers.urlscan import UrlscanProvider
from app.workers.urlscan import poll_pending_urlscan_scans


def _patched_client(handler):
    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_cls(*args, **kwargs)

    return patch("app.enrichment.providers.urlscan.httpx.AsyncClient", side_effect=factory)


def _patched_worker_client(handler):
    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_cls(*args, **kwargs)

    return patch("app.workers.urlscan.httpx.AsyncClient", side_effect=factory)


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
async def test_request_path_marks_pending():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "search" in str(request.url):
            return httpx.Response(200, json=_search_response())
        if request.method == "POST" and "/scan/" in str(request.url):
            return httpx.Response(200, json={"uuid": "abc-uuid", "api": "x"})
        return httpx.Response(500)

    with _patched_client(handler):
        prov = UrlscanProvider(api_key="user-key")
        out = await prov.enrich("url", "https://example.com/")

    assert "rescan" in out
    rescan = out["rescan"]
    assert rescan["status"] == "requested/pending"
    assert rescan["scan_id"] == "abc-uuid"
    assert rescan["errors"] == []
    assert rescan["before"]["page_ip"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_pending_scan_poller_updates_cache():
    payload = _result_payload()
    row = type("Row", (), {})()
    row.normalized = {
        "results": [_search_response()["results"][0]],
        "rescan": {
            "status": "requested/pending",
            "scan_id": "abc-uuid",
            "scan_url": "https://urlscan.io/api/v1/result/abc-uuid/",
            "before": _search_response()["results"][0],
        },
    }
    row.raw_response = row.normalized
    row.expires_at = None

    class FakeScalarResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class FakeExecResult:
        def __init__(self, rows):
            self._rows = rows

        def scalars(self):
            return FakeScalarResult(self._rows)

    class FakeDB:
        def __init__(self, rows):
            self.rows = rows
            self.committed = False

        async def execute(self, _stmt):
            return FakeExecResult(self.rows)

        async def commit(self):
            self.committed = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    fake_db = FakeDB([row])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "abc-uuid" in str(request.url):
            return httpx.Response(200, json=payload)
        return httpx.Response(404)

    with patch("app.workers.urlscan.AsyncSessionLocal", lambda: fake_db), _patched_worker_client(handler):
        result = await poll_pending_urlscan_scans({})

    assert result == {"checked": 1, "updated": 1}
    assert fake_db.committed is True
    assert row.normalized["rescan"]["status"] == "complete"
    assert row.normalized["rescan"]["after"]["page_ip"] == "2.2.2.2"
    assert row.raw_response == payload
