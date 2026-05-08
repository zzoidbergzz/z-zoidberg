import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from app.digests.scheduler import is_due, compute_next_run


def make_sub(active: bool, next_run_at=None, frequency="daily"):
    sub = MagicMock()
    sub.active = active
    sub.next_run_at = next_run_at
    sub.frequency = frequency
    return sub


def test_is_due_active_no_next_run():
    sub = make_sub(active=True, next_run_at=None)
    assert is_due(sub) is True


def test_is_due_inactive():
    sub = make_sub(active=False)
    assert is_due(sub) is False


def test_is_due_future_next_run():
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    sub = make_sub(active=True, next_run_at=future)
    assert is_due(sub) is False


def test_is_due_past_next_run():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    sub = make_sub(active=True, next_run_at=past)
    assert is_due(sub) is True


def test_compute_next_run_daily():
    nxt = compute_next_run("daily")
    diff = nxt - datetime.now(timezone.utc)
    assert timedelta(hours=23) < diff < timedelta(hours=25)


def test_compute_next_run_weekly():
    nxt = compute_next_run("weekly")
    diff = nxt - datetime.now(timezone.utc)
    assert timedelta(days=6) < diff < timedelta(days=8)


def test_compute_next_run_hourly():
    nxt = compute_next_run("hourly")
    diff = nxt - datetime.now(timezone.utc)
    assert timedelta(minutes=59) < diff < timedelta(minutes=61)
