"""Parsers for real-world log formats: Zeek, Windows Event Logs, SSH."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from soclsim.logs.parsers import NormalizedEvent
from soclsim.utils.time import parse_ts, to_iso_utc


def parse_zeek_conn_log(file_path: Path) -> Iterator[NormalizedEvent]:
    """Parse Zeek conn.log (TSV format).
    
    Format: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, ...
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        # Skip header comments
        for line in f:
            if line.startswith("#fields"):
                fields = line.split()[1:]  # Get field names
                break
        
        # Read data
        reader = csv.DictReader(f, fieldnames=fields, delimiter="\t")
        for row in reader:
            if row.get("ts", "").startswith("#"):
                continue  # Skip comments
            
            try:
                ts = float(row.get("ts", 0))
                orig_ip = row.get("id.orig_h", "")
                resp_ip = row.get("id.resp_h", "")
                resp_port = row.get("id.resp_p", "")
                proto = row.get("proto", "").lower()
                duration = float(row.get("duration", 0))
                orig_bytes = int(row.get("orig_bytes", 0))
                resp_bytes = int(row.get("resp_bytes", 0))
                
                # Convert timestamp
                from datetime import datetime, timezone
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                ts_iso = to_iso_utc(dt)
                
                # Create normalized event
                yield NormalizedEvent(
                    ts=ts_iso,
                    source="network",
                    event_type="connection",
                    user=None,
                    ip=orig_ip,
                    host=None,
                    fields={
                        "dst_ip": resp_ip,
                        "dst_port": int(resp_port) if resp_port.isdigit() else None,
                        "protocol": proto,
                        "duration": duration,
                        "bytes": orig_bytes + resp_bytes,
                        "orig_bytes": orig_bytes,
                        "resp_bytes": resp_bytes,
                    },
                    event_id=f"zeek_{ts}_{orig_ip}_{resp_ip}",
                )
            except (ValueError, KeyError):
                continue


def parse_zeek_json_log(file_path: Path) -> Iterator[NormalizedEvent]:
    """Parse Zeek logs in JSON format (one JSON object per line)."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            try:
                data = json.loads(line)
                
                # Extract common fields
                ts = data.get("ts", 0)
                orig_ip = data.get("id.orig_h", "")
                resp_ip = data.get("id.resp_h", "")
                
                # Convert timestamp
                from datetime import datetime, timezone
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                ts_iso = to_iso_utc(dt)
                
                # Determine event type from log type
                log_type = data.get("_path", "conn")
                event_type = "connection" if log_type == "conn" else log_type
                
                yield NormalizedEvent(
                    ts=ts_iso,
                    source="network",
                    event_type=event_type,
                    user=None,
                    ip=orig_ip,
                    host=None,
                    fields={
                        "dst_ip": resp_ip,
                        "dst_port": data.get("id.resp_p"),
                        "protocol": data.get("proto", "").lower(),
                        **{k: v for k, v in data.items() if k not in ("ts", "id.orig_h", "id.resp_h", "_path")},
                    },
                    event_id=f"zeek_{ts}_{orig_ip}_{resp_ip}",
                )
            except (json.JSONDecodeError, ValueError, KeyError):
                continue


def parse_windows_event_log(file_path: Path) -> Iterator[NormalizedEvent]:
    """Parse Windows Event Log exported as CSV.
    
    Expected columns: TimeGenerated, EventID, Computer, AccountName, SourceIPAddress, etc.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # Parse timestamp (format varies)
                time_str = row.get("TimeGenerated", "")
                ts_iso = parse_ts(time_str).isoformat().replace("+00:00", "Z")
                
                event_id = int(row.get("EventID", 0))
                computer = row.get("Computer", "")
                account = row.get("AccountName", "") or row.get("TargetUserName", "")
                source_ip = row.get("SourceIPAddress", "") or row.get("IpAddress", "")
                
                # Map EventID to event type
                event_type = "login_success" if event_id == 4624 else "login_failure" if event_id == 4625 else f"event_{event_id}"
                
                yield NormalizedEvent(
                    ts=ts_iso,
                    source="auth",
                    event_type=event_type,
                    user=account if account else None,
                    ip=source_ip if source_ip else None,
                    host=computer,
                    fields={
                        "event_id": event_id,
                        "computer": computer,
                        "logon_type": row.get("LogonType"),
                        "authentication_package": row.get("AuthenticationPackageName"),
                        **{k: v for k, v in row.items() if k not in ("TimeGenerated", "EventID", "Computer", "AccountName", "SourceIPAddress")},
                    },
                    event_id=f"win_{event_id}_{ts_iso}_{account}",
                )
            except (ValueError, KeyError):
                continue


def parse_ssh_auth_log(file_path: Path) -> Iterator[NormalizedEvent]:
    """Parse SSH auth.log (Linux authentication logs).
    
    Format: Jan 15 08:00:00 hostname sshd[12345]: message
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            
            try:
                # Parse syslog format
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                # Extract timestamp (simplified - assumes current year)
                month_str, day_str, time_str = parts[0], parts[1], parts[2]
                hostname = parts[3]
                process = parts[4].rstrip(":")
                message = " ".join(parts[5:])
                
                # Parse time
                from datetime import datetime, timezone
                current_year = datetime.now().year
                month_map = {
                    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
                }
                month = month_map.get(month_str, 1)
                day = int(day_str)
                hour, minute, second = map(int, time_str.split(":"))
                dt = datetime(current_year, month, day, hour, minute, second, tzinfo=timezone.utc)
                ts_iso = to_iso_utc(dt)
                
                # Extract user and IP from message
                user = None
                ip = None
                event_type = "authentication"
                
                if "Failed password" in message or "Invalid user" in message:
                    event_type = "login_failure"
                    # Extract user: "Failed password for user from IP"
                    if "for" in message:
                        user_idx = message.split().index("for") + 1
                        user = message.split()[user_idx] if user_idx < len(message.split()) else None
                    if "from" in message:
                        ip_idx = message.split().index("from") + 1
                        ip = message.split()[ip_idx] if ip_idx < len(message.split()) else None
                elif "Accepted password" in message or "Accepted publickey" in message:
                    event_type = "login_success"
                    if "for" in message:
                        user_idx = message.split().index("for") + 1
                        user = message.split()[user_idx] if user_idx < len(message.split()) else None
                    if "from" in message:
                        ip_idx = message.split().index("from") + 1
                        ip = message.split()[ip_idx] if ip_idx < len(message.split()) else None
                
                yield NormalizedEvent(
                    ts=ts_iso,
                    source="auth",
                    event_type=event_type,
                    user=user,
                    ip=ip,
                    host=hostname,
                    fields={
                        "process": process,
                        "message": message,
                    },
                    event_id=f"ssh_{ts_iso}_{user}_{ip}",
                )
            except (ValueError, IndexError, KeyError):
                continue


def detect_log_format(file_path: Path) -> str:
    """Detect log format from file extension and content."""
    ext = file_path.suffix.lower()
    name = file_path.name.lower()
    
    if "zeek" in name or "conn.log" in name:
        # Check if JSON or TSV
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            first_line = f.readline()
            if first_line.strip().startswith("{"):
                return "zeek_json"
            return "zeek_tsv"
    
    if "windows" in name or "event" in name or ext == ".csv":
        # Check if Windows Event Log CSV
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            first_line = f.readline()
            if "TimeGenerated" in first_line or "EventID" in first_line:
                return "windows_event"
    
    if "ssh" in name or "auth.log" in name or "secure" in name:
        return "ssh_auth"
    
    return "unknown"


def parse_real_log(file_path: Path) -> Iterator[NormalizedEvent]:
    """Parse a real log file, auto-detecting format."""
    format_type = detect_log_format(file_path)
    
    if format_type == "zeek_tsv":
        yield from parse_zeek_conn_log(file_path)
    elif format_type == "zeek_json":
        yield from parse_zeek_json_log(file_path)
    elif format_type == "windows_event":
        yield from parse_windows_event_log(file_path)
    elif format_type == "ssh_auth":
        yield from parse_ssh_auth_log(file_path)
    else:
        raise ValueError(f"Unknown log format for {file_path}")

