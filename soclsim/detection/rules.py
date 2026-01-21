from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from soclsim.utils.time import parse_ts


@dataclass
class RuleAlert:
    rule_name: str
    confidence: float
    description: str
    entities: Dict[str, Any]  # user, ip, etc.
    evidence: List[Dict[str, Any]]
    start_ts: str
    end_ts: str


def detect_brute_force(events: List[Dict[str, Any]], window_minutes: int = 5, threshold: int = 5) -> List[RuleAlert]:
    alerts: List[RuleAlert] = []
    
    ip_windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    for event in events:
        if event.get("source") != "auth":
            continue
        if event.get("event_type") not in ("login_failure", "authentication_failure"):
            continue
        
        ip = event.get("ip")
        if not ip:
            continue
        
        ip_windows[ip].append(event)
    
    for ip, ip_events in ip_windows.items():
        ip_events.sort(key=lambda e: parse_ts(e["ts"]))
        
        window_start_idx = 0
        for i, event in enumerate(ip_events):
            window_start = parse_ts(event["ts"])
            window_end = window_start + timedelta(minutes=window_minutes)
            
            failures_in_window = []
            for j in range(window_start_idx, len(ip_events)):
                evt = ip_events[j]
                evt_ts = parse_ts(evt["ts"])
                if evt_ts > window_end:
                    break
                failures_in_window.append(evt)
            
            if len(failures_in_window) >= threshold:
                confidence = min(1.0, len(failures_in_window) / (threshold * 2))
                
                alerts.append(RuleAlert(
                    rule_name="brute_force",
                    confidence=confidence,
                    description=f"Brute force detected: {len(failures_in_window)} failed logins from {ip} in {window_minutes} minutes",
                    entities={"ip": ip, "user": None},
                    evidence=failures_in_window[:20],
                    start_ts=failures_in_window[0]["ts"],
                    end_ts=failures_in_window[-1]["ts"],
                ))
                window_start_idx = i + 1
                break
    
    return alerts


def detect_impossible_travel(events: List[Dict[str, Any]], max_speed_kmh: float = 900.0) -> List[RuleAlert]:
    alerts: List[RuleAlert] = []
    
    user_logins: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    for event in events:
        if event.get("source") != "auth":
            continue
        if event.get("event_type") not in ("login_success", "authentication_success"):
            continue
        
        user = event.get("user")
        ip = event.get("ip")
        if not user or not ip:
            continue
        
        user_logins[user].append(event)
    
    for user, logins in user_logins.items():
        if len(logins) < 2:
            continue
        
        logins.sort(key=lambda e: parse_ts(e["ts"]))
        
        for i in range(len(logins) - 1):
            login1 = logins[i]
            login2 = logins[i + 1]
            
            ip1 = login1.get("ip")
            ip2 = login2.get("ip")
            
            if ip1 == ip2:
                continue
            
            ts1 = parse_ts(login1["ts"])
            ts2 = parse_ts(login2["ts"])
            time_diff_hours = (ts2 - ts1).total_seconds() / 3600.0
            
            if time_diff_hours <= 0:
                continue
            
            min_distance_km = 100.0
            
            required_speed = min_distance_km / time_diff_hours
            
            if required_speed > max_speed_kmh:
                confidence = min(1.0, required_speed / (max_speed_kmh * 2))
                
                alerts.append(RuleAlert(
                    rule_name="impossible_travel",
                    confidence=confidence,
                    description=f"Impossible travel: {user} logged in from {ip1} then {ip2} within {time_diff_hours:.2f} hours (required speed: {required_speed:.0f} km/h)",
                    entities={"user": user, "ips": [ip1, ip2]},
                    evidence=[login1, login2],
                    start_ts=login1["ts"],
                    end_ts=login2["ts"],
                ))
    
    return alerts


def detect_lateral_movement(events: List[Dict[str, Any]], window_minutes: int = 10, threshold: int = 3) -> List[RuleAlert]:
    alerts: List[RuleAlert] = []
    
    ip_windows: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "hosts": set(),
        "events": [],
        "start_ts": None,
        "end_ts": None,
    })
    
    for event in events:
        source_ip = event.get("ip")
        host = event.get("host")
        
        if not source_ip or not host:
            continue
        
        if event.get("source") in ("network", "auth"):
            evt_ts = parse_ts(event["ts"])
            
            window_key = f"{source_ip}_{evt_ts.strftime('%Y%m%d%H%M')}"
            
            ip_windows[window_key]["hosts"].add(host)
            ip_windows[window_key]["events"].append(event)
            
            if not ip_windows[window_key]["start_ts"]:
                ip_windows[window_key]["start_ts"] = event["ts"]
            ip_windows[window_key]["end_ts"] = event["ts"]
    
    for window_key, window_data in ip_windows.items():
        if len(window_data["hosts"]) >= threshold:
            source_ip = window_key.split("_")[0]
            num_hosts = len(window_data["hosts"])
            
            confidence = min(1.0, num_hosts / (threshold * 2))
            
            alerts.append(RuleAlert(
                rule_name="lateral_movement",
                confidence=confidence,
                description=f"Lateral movement detected: {source_ip} accessed {num_hosts} distinct hosts in {window_minutes} minutes",
                entities={"ip": source_ip, "hosts": list(window_data["hosts"])},
                evidence=window_data["events"][:20],
                start_ts=window_data["start_ts"],
                end_ts=window_data["end_ts"],
            ))
    
    return alerts


def run_all_rules(events: List[Dict[str, Any]]) -> List[RuleAlert]:
    all_alerts: List[RuleAlert] = []
    
    all_alerts.extend(detect_brute_force(events))
    all_alerts.extend(detect_impossible_travel(events))
    all_alerts.extend(detect_lateral_movement(events))
    
    return all_alerts

