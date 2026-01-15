from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

from soclsim.config import SETTINGS
from soclsim.utils.time import parse_ts


@dataclass(frozen=True)
class Session:
    session_id: str
    user: Optional[str]
    ip: Optional[str]
    start_ts: str
    end_ts: str
    events: List[Dict]


def sessionize(events: List[Dict]) -> List[Session]:
    """Sessionize events by (user, ip) with inactivity gap threshold.

    Input events are normalized dicts with at least: ts, user, ip, source, event_type, fields, event_id.
    """
    if not events:
        return []

    df = pd.DataFrame(events)
    df["dt"] = df["ts"].map(parse_ts)
    df = df.sort_values(["user", "ip", "dt"], na_position="last").reset_index(drop=True)

    gap = timedelta(minutes=SETTINGS.session_gap_minutes)

    sessions: List[Session] = []
    for (user, ip), g in df.groupby(["user", "ip"], dropna=False, sort=False):
        last_dt: Optional[datetime] = None
        cur: List[Dict] = []
        start_dt: Optional[datetime] = None

        def flush():
            nonlocal cur, start_dt, last_dt
            if not cur or start_dt is None or last_dt is None:
                cur, start_dt, last_dt = [], None, None
                return
            sid = f"sess_{abs(hash((str(user), str(ip), start_dt.isoformat()))) % 10**12:012d}"
            sessions.append(
                Session(
                    session_id=sid,
                    user=None if (isinstance(user, float) and pd.isna(user)) else user,
                    ip=None if (isinstance(ip, float) and pd.isna(ip)) else ip,
                    start_ts=start_dt.isoformat().replace("+00:00", "Z"),
                    end_ts=last_dt.isoformat().replace("+00:00", "Z"),
                    events=cur,
                )
            )
            cur, start_dt, last_dt = [], None, None

        for _, row in g.iterrows():
            dt = row["dt"]
            if start_dt is None:
                start_dt = dt
                last_dt = dt
                cur = [row.drop(labels=["dt"]).to_dict()]
                continue
            assert last_dt is not None
            if dt - last_dt > gap:
                flush()
                start_dt = dt
                last_dt = dt
                cur = [row.drop(labels=["dt"]).to_dict()]
            else:
                last_dt = dt
                cur.append(row.drop(labels=["dt"]).to_dict())

        flush()

    # Sort sessions chronologically
    sessions.sort(key=lambda s: s.start_ts)
    return sessions


def index_by_key(sessions: List[Session]) -> Dict[Tuple[Optional[str], Optional[str]], List[Session]]:
    out: Dict[Tuple[Optional[str], Optional[str]], List[Session]] = {}
    for s in sessions:
        out.setdefault((s.user, s.ip), []).append(s)
    return out


