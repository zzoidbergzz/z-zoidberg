from datetime import datetime, timezone, timedelta
from app.models.digests import DigestSubscription


def is_due(sub: DigestSubscription) -> bool:
    if not sub.active:
        return False
    now = datetime.now(timezone.utc)
    if sub.next_run_at and now < sub.next_run_at:
        return False
    return True


def compute_next_run(frequency: str) -> datetime:
    now = datetime.now(timezone.utc)
    deltas = {
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
        "hourly": timedelta(hours=1),
    }
    delta = deltas.get(frequency, timedelta(days=1))
    return now + delta
