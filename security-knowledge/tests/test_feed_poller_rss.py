"""Tests for the feed_poller RSS/Atom parsing path.

We mock the network fetch and the DB session so the test runs offline.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <link>https://example.com/</link>
    <description>desc</description>
    <item>
      <title>Article One</title>
      <link>https://example.com/one</link>
      <description>summary one</description>
      <pubDate>Mon, 04 May 2026 12:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Article Two</title>
      <link>https://example.com/two</link>
      <description>summary two</description>
      <pubDate>Tue, 05 May 2026 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""


def _make_source(source_type: str = "rss"):
    src = MagicMock()
    src.id = uuid.uuid4()
    src.tenant_id = uuid.uuid4()
    src.url = "https://example.com/feed.xml"
    src.source_type = source_type
    src.fetch_interval_seconds = 3600
    src.last_fetched_at = None
    return src


@pytest.mark.asyncio
async def test_parse_and_enqueue_feed_creates_jobs_and_dedupes():
    from app.workers import feed_poller

    src = _make_source("rss")

    enqueue_calls: list[tuple] = []

    class FakePool:
        async def enqueue_job(self, *args, **kwargs):
            enqueue_calls.append((args, kwargs))

        async def aclose(self):
            pass

    # Stub DB session.  First entry: no existing doc/job (returns None
    # twice per entry — once for ParsedDocument lookup, once for
    # IngestionJob lookup).  Second entry: ParsedDocument hit (skip).
    added: list = []

    class FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar_one_or_none(self):
            return self._value

    # Sequence: entry1 doc=None, entry1 job=None,
    #           entry2 doc=<uuid> (already ingested → skip)
    results_seq = [None, None, uuid.uuid4()]

    class FakeDB:
        def __init__(self):
            self._i = 0

        async def execute(self, _stmt):
            v = results_seq[self._i] if self._i < len(results_seq) else None
            self._i += 1
            return FakeResult(v)

        def add(self, obj):
            added.append(obj)

        async def flush(self):
            pass

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    fake_db = FakeDB()

    with patch.object(feed_poller, "AsyncSessionLocal", lambda: fake_db), patch(
        "arq.create_pool", AsyncMock(return_value=FakePool())
    ):
        new_count = await feed_poller._parse_and_enqueue_feed(src, SAMPLE_RSS)

    # Only the first entry was new
    assert new_count == 1
    assert len(enqueue_calls) == 1
    args, _ = enqueue_calls[0]
    assert args[0] == "process_ingest_job"
    # One IngestionJob was added with the correct URL and tenant
    job_rows = [a for a in added if hasattr(a, "source_url")]
    assert len(job_rows) == 1
    assert job_rows[0].source_url == "https://example.com/one"
    assert job_rows[0].tenant_id == src.tenant_id
    assert job_rows[0].source_id == src.id
    assert job_rows[0].payload["title"] == "Article One"
    assert job_rows[0].payload["published_at"] is not None


@pytest.mark.asyncio
async def test_fetch_source_parses_rss_when_source_type_is_feed():
    from app.workers import feed_poller

    src = _make_source("feed")

    fake_result = MagicMock()
    fake_result.ok = True
    fake_result.status_code = 200
    fake_result.text = SAMPLE_RSS
    fake_result.captcha_detected = False
    fake_result.error = None

    with patch.object(feed_poller, "fetch", AsyncMock(return_value=fake_result)), patch.object(
        feed_poller, "_parse_and_enqueue_feed", AsyncMock(return_value=2)
    ) as mock_parse:
        outcome, new_items = await feed_poller._fetch_source(src)

    assert mock_parse.await_count == 1
    assert new_items == 2
    assert outcome.status == "ok"
    assert outcome.items_fetched == 2


@pytest.mark.asyncio
async def test_fetch_source_does_not_parse_non_feed_source():
    from app.workers import feed_poller

    src = _make_source("html")

    fake_result = MagicMock()
    fake_result.ok = True
    fake_result.status_code = 200
    fake_result.text = "<html>not a feed</html>"
    fake_result.captcha_detected = False
    fake_result.error = None

    with patch.object(feed_poller, "fetch", AsyncMock(return_value=fake_result)), patch.object(
        feed_poller, "_parse_and_enqueue_feed", AsyncMock(return_value=0)
    ) as mock_parse:
        outcome, new_items = await feed_poller._fetch_source(src)

    assert mock_parse.await_count == 0
    assert new_items == 0
    assert outcome.status == "ok"
