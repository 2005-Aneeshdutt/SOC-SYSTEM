from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

from soclsim.config import SETTINGS
from soclsim.utils.time import hour_of_day_utc, parse_ts


@dataclass(frozen=True)
class WindowFeatures:
    """Features for a (user, ip) time window."""

    key_user: Optional[str]
    key_ip: Optional[str]
    start_ts: str
    end_ts: str
    x: np.ndarray
    feature_names: List[str]
    evidence: List[Dict]


def _floor_time(dt: datetime, minutes: int) -> datetime:
    m = (dt.minute // minutes) * minutes
    return dt.replace(minute=m, second=0, microsecond=0)


def build_user_hour_profile(events: List[Dict]) -> Dict[str, Tuple[float, float]]:
    """Estimate typical login hour distribution per user for deviation scoring.

    Returns map: user -> (mean_hour, std_hour) computed on login_success events.
    """
    buckets: Dict[str, List[int]] = {}
    for e in events:
        if e.get("source") == "auth" and e.get("event_type") == "login_success" and e.get("user"):
            dt = parse_ts(e["ts"])
            buckets.setdefault(e["user"], []).append(hour_of_day_utc(dt))

    out: Dict[str, Tuple[float, float]] = {}
    for u, hours in buckets.items():
        if len(hours) < 5:
            continue
        mu = float(np.mean(hours))
        sd = float(np.std(hours) + 1e-6)
        out[u] = (mu, sd)
    return out


def build_command_frequency(events: List[Dict]) -> Dict[str, int]:
    """Global command frequencies used to compute 'rarity'."""
    freq: Dict[str, int] = {}
    for e in events:
        if e.get("source") == "process":
            cmd = (e.get("fields") or {}).get("command")
            if cmd:
                freq[str(cmd)] = freq.get(str(cmd), 0) + 1
    return freq


def windowize(events: List[Dict]) -> List[WindowFeatures]:
    """Convert normalized events into fixed-window feature vectors per (user, ip)."""
    if not events:
        return []

    minutes = SETTINGS.window_minutes
    cmd_freq = build_command_frequency(events)
    user_hour = build_user_hour_profile(events)

    parsed = []
    for e in events:
        dt = parse_ts(e["ts"])
        w0 = _floor_time(dt, minutes)
        w1 = w0 + timedelta(minutes=minutes)
        parsed.append((e.get("user"), e.get("ip"), w0, w1, dt, e))

    # group by key + window start
    groups: Dict[Tuple[Optional[str], Optional[str], datetime], List[Tuple[datetime, Dict]]] = {}
    for user, ip, w0, _, dt, e in parsed:
        groups.setdefault((user, ip, w0), []).append((dt, e))

    feature_names = [
        "auth_failures",
        "auth_successes",
        "distinct_users_in_window",  # network-only windows will likely be 0/1
        "distinct_dst_ips",
        "distinct_dst_ports",
        "deny_rate",
        "bytes_sum",
        "process_exec_count",
        "rare_command_count",
        "max_rare_command_score",
        "login_hour_deviation_z",
        "event_sequence_len",
        "sources_count",
    ]

    out: List[WindowFeatures] = []
    for (user, ip, w0), items in sorted(groups.items(), key=lambda kv: kv[0][2]):
        items.sort(key=lambda t: t[0])
        w1 = (w0 + timedelta(minutes=minutes)).replace(tzinfo=timezone.utc)

        auth_f = 0
        auth_s = 0
        users_set = set()
        dst_ips = set()
        dst_ports = set()
        denies = 0
        net = 0
        bytes_sum = 0
        proc = 0
        rare_cnt = 0
        max_rare = 0.0
        sources = set()

        # login deviation: if a success exists in this window, compute deviation vs profile
        dev_z = 0.0

        evidence: List[Dict] = []
        for dt, e in items:
            sources.add(e.get("source"))
            evidence.append(e)
            if e.get("user"):
                users_set.add(e["user"])

            if e.get("source") == "auth":
                if e.get("event_type") == "login_failure":
                    auth_f += 1
                elif e.get("event_type") == "login_success":
                    auth_s += 1
                    if e.get("user") in user_hour:
                        mu, sd = user_hour[e["user"]]
                        dev_z = max(dev_z, abs((hour_of_day_utc(dt) - mu) / sd))

            if e.get("source") == "network":
                net += 1
                f = e.get("fields") or {}
                if f.get("dst_ip"):
                    dst_ips.add(f["dst_ip"])
                if f.get("dst_port"):
                    dst_ports.add(int(f["dst_port"]))
                if f.get("action") == "deny":
                    denies += 1
                bytes_sum += int(f.get("bytes") or 0)

            if e.get("source") == "process":
                proc += 1
                cmd = (e.get("fields") or {}).get("command")
                if cmd:
                    c = str(cmd)
                    f = cmd_freq.get(c, 1)
                    rarity = 1.0 / float(f)
                    # threshold tuned for synthetic distribution: rare commands appear few times
                    if f <= 3:
                        rare_cnt += 1
                        max_rare = max(max_rare, rarity)

        deny_rate = (denies / net) if net else 0.0
        seq_len = len(items)
        x = np.array(
            [
                float(auth_f),
                float(auth_s),
                float(len(users_set)),
                float(len(dst_ips)),
                float(len(dst_ports)),
                float(deny_rate),
                float(bytes_sum),
                float(proc),
                float(rare_cnt),
                float(max_rare),
                float(dev_z),
                float(seq_len),
                float(len(sources)),
            ],
            dtype=np.float32,
        )

        out.append(
            WindowFeatures(
                key_user=user,
                key_ip=ip,
                start_ts=w0.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                end_ts=w1.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                x=x,
                feature_names=feature_names,
                evidence=evidence,
            )
        )
    return out


