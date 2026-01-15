from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from soclsim.utils.time import parse_ts, to_iso_utc


NormalizedSource = Literal["auth", "network", "process"]


@dataclass(frozen=True)
class NormalizedEvent:
    """Canonical event used by the rest of the pipeline."""

    ts: str
    source: NormalizedSource
    event_type: str
    user: Optional[str]
    ip: Optional[str]
    host: Optional[str]
    fields: Dict[str, Any]
    event_id: str


def _stable_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"|")
    return h.hexdigest()[:16]


def normalize_user(user: Optional[str]) -> Optional[str]:
    if not user:
        return None
    u = user.strip().lower()
    return u or None


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return ip.strip()


def parse_auth(raw: Dict[str, Any]) -> NormalizedEvent:
    dt = parse_ts(str(raw["ts"]))
    user = normalize_user(raw.get("user"))
    ip = normalize_ip(raw.get("ip"))
    event_type = str(raw.get("event", "auth_event"))
    host = raw.get("host")
    fields = {
        "method": raw.get("method"),
        "reason": raw.get("reason"),
        "app": raw.get("app"),
    }
    ts = to_iso_utc(dt)
    eid = _stable_id("auth", ts, event_type, user or "-", ip or "-", str(host or "-"), str(fields.get("app") or "-"))
    return NormalizedEvent(
        ts=ts,
        source="auth",
        event_type=event_type,
        user=user,
        ip=ip,
        host=str(host) if host else None,
        fields=fields,
        event_id=eid,
    )


def parse_network(raw: Dict[str, Any]) -> NormalizedEvent:
    dt = parse_ts(str(raw["ts"]))
    src_ip = normalize_ip(raw.get("src_ip"))
    dst_ip = normalize_ip(raw.get("dst_ip"))
    event_type = str(raw.get("event", "netflow"))
    fields = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(raw.get("dst_port", 0) or 0),
        "proto": raw.get("proto"),
        "bytes": int(raw.get("bytes", 0) or 0),
        "action": raw.get("action"),
        "sensor": raw.get("sensor"),
    }
    ts = to_iso_utc(dt)
    eid = _stable_id(
        "network",
        ts,
        event_type,
        src_ip or "-",
        dst_ip or "-",
        str(fields["dst_port"]),
        str(fields.get("proto") or "-"),
    )
    # For correlation, treat ip as src_ip and user is unknown at network layer.
    return NormalizedEvent(
        ts=ts,
        source="network",
        event_type=event_type,
        user=None,
        ip=src_ip,
        host=None,
        fields=fields,
        event_id=eid,
    )


def parse_process(raw: Dict[str, Any]) -> NormalizedEvent:
    dt = parse_ts(str(raw["ts"]))
    user = normalize_user(raw.get("user"))
    ip = normalize_ip(raw.get("ip"))
    event_type = str(raw.get("event", "process_exec"))
    host = raw.get("host")
    command = raw.get("command")
    fields = {
        "command": command,
        "parent": raw.get("parent"),
    }
    ts = to_iso_utc(dt)
    eid = _stable_id("process", ts, event_type, user or "-", ip or "-", str(host or "-"), str(command or "-"))
    return NormalizedEvent(
        ts=ts,
        source="process",
        event_type=event_type,
        user=user,
        ip=ip,
        host=str(host) if host else None,
        fields=fields,
        event_id=eid,
    )


def parse_any(source: NormalizedSource, raw: Dict[str, Any]) -> NormalizedEvent:
    if source == "auth":
        return parse_auth(raw)
    if source == "network":
        return parse_network(raw)
    if source == "process":
        return parse_process(raw)
    raise ValueError(f"Unsupported source: {source}")


