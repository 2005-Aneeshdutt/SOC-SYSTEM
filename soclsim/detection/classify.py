from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import numpy as np

from soclsim.correlation.mitre import mitre_for_keys


def classify_detection(
    window_features: Optional[Dict[str, float]],
    evidence: List[Dict],
    window_score: float,
    sequence_score: float,
) -> Tuple[str, str, List[str]]:
    """
    Classify detection into type, category, and MITRE keys.

    Returns:
        (detection_type, category, mitre_keys)
    """
    detection_type = "unknown"
    category = "unknown"
    mitre_keys: List[str] = []

    if window_features:
        fn = window_features
        auth_failures = fn.get("auth_failures", 0.0)
        auth_successes = fn.get("auth_successes", 0.0)
        distinct_dst_ports = fn.get("distinct_dst_ports", 0.0)
        distinct_dst_ips = fn.get("distinct_dst_ips", 0.0)
        bytes_sum = fn.get("bytes_sum", 0.0)
        rare_command_count = fn.get("rare_command_count", 0.0)
        process_exec_count = fn.get("process_exec_count", 0.0)
    else:
        auth_failures = 0.0
        auth_successes = 0.0
        distinct_dst_ports = 0.0
        distinct_dst_ips = 0.0
        bytes_sum = 0.0
        rare_command_count = 0.0
        process_exec_count = 0.0

    # Check evidence for additional signals
    user = None
    is_service_account = False
    has_admin_ports = False
    has_external_dst = False

    for e in evidence:
        u = e.get("user")
        if u and (u.startswith("svc_") or u.startswith("service_") or "backup" in u.lower() or "deploy" in u.lower()):
            is_service_account = True
            user = u

        if e.get("source") == "network":
            f = e.get("fields") or {}
            port = f.get("dst_port")
            if port and port in [22, 3389, 5985, 5986, 445, 135]:  # SSH, RDP, WinRM, SMB, RPC
                has_admin_ports = True
            if f.get("dst_ip") and not f.get("dst_ip", "").startswith(("10.", "192.168.", "172.")):
                has_external_dst = True

    # Classification rules (ordered by priority)

    # 1. Brute force / credential stuffing - many logins from same IP
    if auth_failures >= 15:
        detection_type = "credential_stuffing"
        category = "authentication"
        mitre_keys = ["bruteforce"]
    elif auth_failures >= 10 or (auth_failures >= 5 and auth_successes >= 1):
        detection_type = "brute_force_login"
        category = "authentication"
        mitre_keys = ["bruteforce"]
        if auth_successes >= 1:
            mitre_keys.append("valid_accounts")

    # 2. Port scanning
    elif distinct_dst_ports >= 5 and bytes_sum < 1_000_000:  # Many ports, low bytes = scanning
        detection_type = "port_scan"
        category = "network_recon"
        mitre_keys = ["port_scan"]

    # 3. Lateral movement attempt
    elif distinct_dst_ips >= 3 and has_admin_ports:
        detection_type = "lateral_movement_attempt"
        category = "lateral_movement"
        mitre_keys = ["remote_services"]

    # 4. Data exfiltration spike
    elif bytes_sum > 10_000_000 or (bytes_sum > 5_000_000 and has_external_dst):  # Large data transfer
        detection_type = "exfil_spike"
        category = "exfiltration"
        mitre_keys = ["ingress_tool_transfer"]

    # 5. Service account abuse
    elif is_service_account and (rare_command_count > 0 or process_exec_count > 10):
        detection_type = "service_acct_abuse"
        category = "privilege_misuse"
        mitre_keys = ["valid_accounts", "account_manipulation"]

    # 6. Generic anomaly (fallback) - try to be more specific using evidence patterns
    else:
        if window_score > 0.7 or sequence_score > 0.7:
            # Analyze evidence patterns for semantic detection
            has_network = any(e.get("source") == "network" for e in evidence)
            has_auth = any(e.get("source") == "auth" for e in evidence)
            has_process = any(e.get("source") == "process" for e in evidence)
            
            # Count unique hosts/IPs from evidence
            unique_hosts = set()
            unique_ips = set()
            login_events = 0
            for e in evidence:
                if e.get("host"):
                    unique_hosts.add(e["host"])
                if e.get("ip"):
                    unique_ips.add(e["ip"])
                if e.get("source") == "auth" and e.get("event_type") in ("login_success", "login_failure"):
                    login_events += 1
            
            # Pattern: Many logins from same IP = brute force
            if has_auth and login_events >= 5 and len(unique_ips) <= 2:
                detection_type = "bruteforce"
                category = "authentication"
                mitre_keys = ["bruteforce"]
            # Pattern: Same user, many hosts = lateral movement
            elif len(unique_hosts) >= 3 or (distinct_dst_ips >= 3 and has_admin_ports):
                detection_type = "lateral_movement"
                category = "lateral_movement"
                mitre_keys = ["remote_services"]
            # Pattern: Large bytes spike = data exfiltration
            elif bytes_sum > 5_000_000:
                detection_type = "exfil_spike"
                category = "exfiltration"
                mitre_keys = ["ingress_tool_transfer"]
            # Pattern: Service account + process = abnormal service usage
            elif is_service_account and has_process:
                detection_type = "abnormal_service_usage"
                category = "privilege_misuse"
                mitre_keys = ["valid_accounts"]
            # Pattern: Network scanning
            elif has_network and distinct_dst_ports >= 3 and bytes_sum < 500_000:
                detection_type = "port_scan"
                category = "network_recon"
                mitre_keys = ["port_scan"]
            else:
                detection_type = "anomalous_behavior"
                category = "suspicious_activity"
                mitre_keys = ["valid_accounts"]  # Generic fallback

    return detection_type, category, mitre_keys


def get_detection_title(detection_type: str, severity: str, user: Optional[str], ip: Optional[str]) -> str:
    """Generate human-readable title for detection."""
    entity = user or ip or "unknown entity"
    titles = {
        "bruteforce": f"{severity.upper()} Brute Force Attack Detected",
        "port_scan": f"{severity.upper()} Port Scanning Activity",
        "lateral_movement": f"{severity.upper()} Lateral Movement Attempt",
        "exfil_spike": f"{severity.upper()} Data Exfiltration Spike",
        "service_acct_abuse": f"{severity.upper()} Service Account Abuse",
        "anomalous_behavior": f"{severity.upper()} Anomalous Behavior Detected",
    }
    base = titles.get(detection_type, f"{severity.upper()} Security Alert")
    return f"{base} - {entity}"

