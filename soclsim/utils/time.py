from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as dtparser


def parse_ts(ts: str) -> datetime:
    """Parse ISO-8601 timestamps and normalize to UTC."""
    dt = dtparser.isoparse(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso_utc(dt: datetime) -> str:
    """Serialize datetime to an ISO string with Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def hour_of_day_utc(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return int(dt.hour)


def safe_parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return parse_ts(ts)
    except Exception:
        return None


