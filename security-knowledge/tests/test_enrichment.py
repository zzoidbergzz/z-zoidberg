import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.enrichment.registry import register, get_provider, list_providers
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.budget import BudgetTracker
from app.enrichment.filters import matches_filter
from app.digests.dsl import DigestFilter, matches as digest_matches


class MockProvider(BaseEnrichmentProvider):
    name = "mock"
    async def enrich(self, entity_id: str, entity_kind: str, tenant_id: str) -> dict:
        return {"mock": True}


def test_register_and_get_provider():
    MockProvider2 = type("MockProvider2", (BaseEnrichmentProvider,), {"name": "mock2"})
    MockProvider2.enrich = AsyncMock(return_value={})
    register(MockProvider2)
    prov = get_provider("mock2")
    assert prov is MockProvider2


def test_list_providers():
    providers = list_providers()
    assert isinstance(providers, list)


@pytest.mark.asyncio
async def test_budget_tracker_allows_first_call():
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_result)
    tracker = BudgetTracker(db)
    allowed = await tracker.check_and_increment("tenant1", "nvd")
    assert allowed is True


def test_digest_filter_matches():
    entity = {"kind": "cve", "name": "CVE-2024-1234", "confidence": 80}
    filt = DigestFilter(entity_kinds=["cve"], min_confidence=70)
    assert digest_matches(entity, filt)


def test_digest_filter_rejects_low_confidence():
    entity = {"kind": "cve", "name": "CVE-2024-9999", "confidence": 30}
    filt = DigestFilter(min_confidence=50)
    assert not digest_matches(entity, filt)


def test_digest_filter_keyword_match():
    entity = {"kind": "malware", "name": "Emotet", "description": "banking trojan", "confidence": 60}
    filt = DigestFilter(keywords=["emotet", "trojan"])
    assert digest_matches(entity, filt)


def test_digest_filter_keyword_no_match():
    entity = {"kind": "malware", "name": "UnknownMalware", "description": "something", "confidence": 60}
    filt = DigestFilter(keywords=["emotet"])
    assert not digest_matches(entity, filt)
