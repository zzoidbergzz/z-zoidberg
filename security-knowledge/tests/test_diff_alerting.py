"""Tests for differential enrichment alerting (app/services/diff_alerting.py)."""
from __future__ import annotations

import uuid
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _hash(v: str) -> str:
    return hashlib.sha256(v.lower().strip().encode()).hexdigest()


class TestDiffHumanSummary:
    def test_added(self):
        from app.services.diff_alerting import _diff_human_summary
        s = _diff_human_summary({"added": {"a": 1, "b": 2}, "removed": {}, "changed": {}})
        assert "2 field(s) added" in s

    def test_removed(self):
        from app.services.diff_alerting import _diff_human_summary
        s = _diff_human_summary({"added": {}, "removed": {"x": 1}, "changed": {}})
        assert "1 field(s) removed" in s

    def test_changed(self):
        from app.services.diff_alerting import _diff_human_summary
        s = _diff_human_summary({"added": {}, "removed": {}, "changed": {"ip": ["1.1.1.1", "2.2.2.2"]}})
        assert "1 field(s) changed" in s

    def test_no_changes(self):
        from app.services.diff_alerting import _diff_human_summary
        s = _diff_human_summary({"added": {}, "removed": {}, "changed": {}})
        assert s == "no changes"

    def test_combined(self):
        from app.services.diff_alerting import _diff_human_summary
        s = _diff_human_summary({"added": {"a": 1}, "removed": {"b": 2}, "changed": {"c": [3, 4]}})
        assert "added" in s
        assert "removed" in s
        assert "changed" in s


class TestNotifyDiffWatchers:
    @pytest.mark.asyncio
    async def test_no_watches_returns_zero(self):
        from app.services.diff_alerting import notify_diff_watchers

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        count = await notify_diff_watchers(
            entity_value="1.2.3.4",
            entity_kind="ip_address",
            provider="shodan",
            diff_summary={"added": {"open_ports": [80]}, "removed": {}, "changed": {}},
            has_changes=True,
            db=mock_db,
        )
        assert count == 0

    @pytest.mark.asyncio
    async def test_no_changes_returns_zero(self):
        from app.services.diff_alerting import notify_diff_watchers

        mock_db = AsyncMock()
        count = await notify_diff_watchers(
            entity_value="1.2.3.4",
            entity_kind="ip_address",
            provider="shodan",
            diff_summary={"added": {}, "removed": {}, "changed": {}},
            has_changes=False,
            db=mock_db,
        )
        assert count == 0
        mock_db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_inbox_item_created_for_watcher(self):
        from app.services.diff_alerting import notify_diff_watchers

        # Mock a watch with notify_inbox=True
        watch = MagicMock()
        watch.id = uuid.uuid4()
        watch.user_id = uuid.uuid4()
        watch.tenant_id = uuid.uuid4()
        watch.notify_inbox = True
        watch.notify_webhook = False

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [watch]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()

        with patch("app.services.diff_alerting.InboxItem") as MockInbox:
            MockInbox.return_value = MagicMock()
            count = await notify_diff_watchers(
                entity_value="evil.com",
                entity_kind="domain",
                provider="virustotal",
                diff_summary={"added": {"new_attr": "x"}, "removed": {}, "changed": {}},
                has_changes=True,
                db=mock_db,
            )

        assert count == 1
        mock_db.add.assert_called()

    @pytest.mark.asyncio
    async def test_multiple_watchers_all_notified(self):
        from app.services.diff_alerting import notify_diff_watchers

        watches = []
        for _ in range(3):
            w = MagicMock()
            w.id = uuid.uuid4()
            w.user_id = uuid.uuid4()
            w.tenant_id = uuid.uuid4()
            w.notify_inbox = True
            w.notify_webhook = False
            watches.append(w)

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = watches
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()

        with patch("app.services.diff_alerting.InboxItem", MagicMock(return_value=MagicMock())):
            count = await notify_diff_watchers(
                entity_value="1.2.3.4",
                entity_kind="ip_address",
                provider="shodan",
                diff_summary={"added": {"x": 1}, "removed": {}, "changed": {}},
                has_changes=True,
                db=mock_db,
            )

        assert count == 3


class TestDiffAlertingIntegration:
    def test_hash_ioc(self):
        from app.services.diff_alerting import _hash_ioc
        assert _hash_ioc("  1.2.3.4  ") == _hash_ioc("1.2.3.4")
        assert _hash_ioc("Evil.COM") == _hash_ioc("evil.com")
        assert len(_hash_ioc("test")) == 64
