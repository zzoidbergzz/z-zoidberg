"""Tests for FTS + trigram hybrid search service."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest


def _make_db_execute_mock(*row_batches: list[dict]) -> AsyncMock:
    """Return an AsyncMock for db.execute that yields successive row batches."""
    side_effects = []
    for rows in row_batches:
        result = MagicMock()
        result.mappings.return_value.all.return_value = rows
        side_effects.append(result)
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=side_effects)
    return db


@pytest.mark.asyncio
async def test_fts_hit_ranks_above_trigram_only_hit():
    """Entity with high FTS score should sort above claim with low score."""
    from app.services.search import full_text_search

    entity_rows = [
        {"id": "e1", "name": "Log4Shell CVE-2021-44228", "score": 0.87},
    ]
    claim_rows = [
        {"id": "c1", "name": "cve: some tangentially related claim", "score": 0.18},
    ]

    db = _make_db_execute_mock(entity_rows, claim_rows)
    results = await full_text_search(db, "tenant-xyz", "log4shell", limit=10)

    assert len(results) == 2
    # FTS hit (entity, score=0.87) must outrank trigram-only hit (claim, score=0.18)
    assert results[0]["kind"] == "entity"
    assert results[0]["id"] == "e1"
    assert results[0]["score"] == pytest.approx(0.87)
    assert results[1]["kind"] == "claim"
    assert results[1]["score"] == pytest.approx(0.18)


@pytest.mark.asyncio
async def test_no_match_returns_empty():
    """Both queries returning no rows should yield an empty result list."""
    from app.services.search import full_text_search

    db = _make_db_execute_mock([], [])
    results = await full_text_search(db, "tenant-xyz", "zzznomatch999", limit=10)

    assert results == []


@pytest.mark.asyncio
async def test_limit_applied_after_merge():
    """Result list must not exceed the requested limit after merging both tables."""
    from app.services.search import full_text_search

    entity_rows = [
        {"id": f"e{i}", "name": f"Entity {i}", "score": 1.0 - i * 0.05}
        for i in range(5)
    ]
    claim_rows = [
        {"id": f"c{i}", "name": f"Claim {i}", "score": 0.6 - i * 0.05}
        for i in range(5)
    ]

    db = _make_db_execute_mock(entity_rows, claim_rows)
    results = await full_text_search(db, "tenant-xyz", "anything", limit=6)

    assert len(results) == 6
    # Should be sorted by score descending
    scores = [r["score"] for r in results]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_result_envelope_fields():
    """Each result must contain kind, id, name, score."""
    from app.services.search import full_text_search

    entity_rows = [{"id": "abc", "name": "SomeName", "score": 0.5}]
    db = _make_db_execute_mock(entity_rows, [])
    results = await full_text_search(db, "tenant-xyz", "some", limit=10)

    assert len(results) == 1
    r = results[0]
    assert r["kind"] == "entity"
    assert r["id"] == "abc"
    assert r["name"] == "SomeName"
    assert isinstance(r["score"], float)
