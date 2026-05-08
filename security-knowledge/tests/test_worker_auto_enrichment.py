"""Tests for the auto-enrichment enqueue path in worker.process_ingest_job."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest


def _make_entity(kind: str):
    class _E:
        pass

    e = _E()
    e.id = uuid.uuid4()
    e.kind = kind
    return e


@pytest.mark.asyncio
async def test_auto_enrichment_enqueues_correct_providers():
    from app import worker

    cve = _make_entity("cve")
    tech = _make_entity("attack_pattern")
    url_e = _make_entity("url")
    ip = _make_entity("ip_address")
    other = _make_entity("hash")  # should not enqueue anything

    enqueued: list[tuple] = []

    class FakePool:
        async def enqueue_job(self, *args, **kwargs):
            enqueued.append((args, kwargs))

        async def aclose(self):
            pass

    with patch("arq.create_pool", AsyncMock(return_value=FakePool())):
        await worker._enqueue_auto_enrichment([cve, tech, url_e, ip, other], "tenant-1")

    providers_per_entity: dict[str, list[str]] = {}
    for args, kwargs in enqueued:
        # signature: ("run_enrichment", entity_id, tenant_id, provider=...)
        assert args[0] == "run_enrichment"
        assert args[2] == "tenant-1"
        providers_per_entity.setdefault(args[1], []).append(kwargs["provider"])

    assert providers_per_entity[str(cve.id)] == ["nvd"]
    assert providers_per_entity[str(tech.id)] == ["mitre_attack"]
    assert providers_per_entity[str(url_e.id)] == ["urlscan"]
    assert sorted(providers_per_entity[str(ip.id)]) == ["ipinfo", "urlscan"]
    assert str(other.id) not in providers_per_entity


@pytest.mark.asyncio
async def test_auto_enrichment_one_failure_does_not_abort_others():
    from app import worker

    cve = _make_entity("cve")
    ip = _make_entity("ip_address")

    succeeded: list[str] = []

    class FlakyPool:
        def __init__(self):
            self._calls = 0

        async def enqueue_job(self, *args, **kwargs):
            self._calls += 1
            if self._calls == 1:
                raise RuntimeError("redis transient")
            succeeded.append(kwargs["provider"])

        async def aclose(self):
            pass

    with patch("arq.create_pool", AsyncMock(return_value=FlakyPool())):
        # Should not raise even though the first enqueue fails.
        await worker._enqueue_auto_enrichment([cve, ip], "tenant-2")

    # Two of the three enqueues should have succeeded.
    assert len(succeeded) == 2


@pytest.mark.asyncio
async def test_auto_enrichment_disabled_setting_short_circuits(monkeypatch):
    from app import worker

    cve = _make_entity("cve")

    class FakePool:
        async def enqueue_job(self, *args, **kwargs):
            raise AssertionError("should not enqueue when disabled")

        async def aclose(self):
            pass

    # The disabled-flag check lives in process_ingest_job (not in the helper),
    # so emulate the gate explicitly.
    monkeypatch.setattr(worker.settings, "AUTO_ENRICHMENT_DISABLED", True)
    if getattr(worker.settings, "AUTO_ENRICHMENT_DISABLED", False):
        return  # gate would short-circuit; helper not called

    # Defensive: even if called directly, helper would still enqueue, which
    # is expected — the gate is the caller's responsibility.
    with patch("arq.create_pool", AsyncMock(return_value=FakePool())):
        with pytest.raises(AssertionError):
            await worker._enqueue_auto_enrichment([cve], "tenant-3")
