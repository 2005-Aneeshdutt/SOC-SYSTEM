from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from soclsim.config import SETTINGS
from soclsim.config import THRESHOLDS
from soclsim.correlation.correlate import Signal, correlate
from soclsim.detection.classify import classify_detection, get_detection_title
from soclsim.detection.rules import run_all_rules, RuleAlert
from soclsim.features.sequences import sessions_to_sequences
from soclsim.features.windows import windowize
from soclsim.logs.sessionize import sessionize
from soclsim.models.isoforest import score_isoforest
from soclsim.models.scoring import load_torch_models, score_dense_ae, score_seq_ae
from soclsim.runtime.artifacts import Artifacts
from soclsim.utils.time import parse_ts


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _recent(events: List[Dict[str, Any]], minutes: int) -> List[Dict[str, Any]]:
    if not events:
        return []
    cutoff = _now_utc() - timedelta(minutes=minutes)
    out = []
    for e in events:
        try:
            if parse_ts(e["ts"]) >= cutoff:
                out.append(e)
        except Exception:
            continue
    return out


def _mitre_keys_for_window(w: Dict[str, Any], x: np.ndarray, feature_names: List[str]) -> List[str]:
    fn = {name: float(x[i]) for i, name in enumerate(feature_names)}
    keys: List[str] = []

    if fn.get("auth_failures", 0.0) >= 15 and fn.get("auth_successes", 0.0) >= 1:
        keys += ["bruteforce", "valid_accounts"]
    elif fn.get("auth_failures", 0.0) >= 20:
        keys += ["bruteforce"]

    if fn.get("rare_command_count", 0.0) >= 1:
        keys += ["ingress_tool_transfer"]

    if fn.get("distinct_dst_ports", 0.0) >= 3 and fn.get("bytes_sum", 0.0) > 250_000:
        keys += ["command_and_control"]

    return sorted(set(keys))


def _refine_mitre_from_evidence(keys: List[str], evidence: List[Dict[str, Any]]) -> List[str]:
    for e in evidence:
        if e.get("source") != "process":
            continue
        cmd = str(((e.get("fields") or {}).get("command")) or "")
        if "useradd" in cmd or "chpasswd" in cmd:
            keys.append("account_manipulation")
        if cmd.startswith("ssh ") or "ssh -o" in cmd:
            keys.append("remote_services")
        if "curl " in cmd or "wget " in cmd:
            keys.append("ingress_tool_transfer")
    return sorted(set(keys))


@dataclass(frozen=True)
class DetectionResult:
    signals: List[Signal]
    alerts: List[Dict[str, Any]]
    incidents: List[Dict[str, Any]]


def detect(events: List[Dict[str, Any]], artifacts: Artifacts) -> DetectionResult:
    if not events:
        return DetectionResult(signals=[], alerts=[], incidents=[])

    windows = windowize(events)
    Xw = np.stack([w.x for w in windows], axis=0) if windows else np.zeros((0, len(artifacts.feature_names)))
    iso_s = score_isoforest(artifacts.iso, Xw) if len(windows) else np.zeros((0,), dtype=np.float32)

    seq_model, dense_model = load_torch_models(artifacts.torch)
    dense_s = score_dense_ae(dense_model, Xw) if len(windows) else np.zeros((0,), dtype=np.float32)

    signals: List[Signal] = []
    for i, w in enumerate(windows):
        iso_score = float(iso_s[i])
        dense_score = float(dense_s[i])
        window_score = float(1.0 - (1.0 - iso_score) * (1.0 - dense_score))
        if window_score < THRESHOLDS.signal_min_score:
            continue

        feature_dict = {name: float(w.x[j]) for j, name in enumerate(w.feature_names)}

        mitre_keys = _mitre_keys_for_window({}, w.x, w.feature_names)
        mitre_keys = _refine_mitre_from_evidence(mitre_keys, w.evidence)

        detection_type, category, class_mitre_keys = classify_detection(
            feature_dict, w.evidence, window_score, 0.0
        )
        all_mitre_keys = sorted(set(mitre_keys + class_mitre_keys))

        signals.append(
            Signal(
                start_ts=w.start_ts,
                end_ts=w.end_ts,
                user=w.key_user,
                ip=w.key_ip,
                kind="window_anomaly",
                score=window_score,
                window_score=window_score,
                sequence_score=0.0,
                feature_vector=w.x.tolist(),
                feature_names=w.feature_names,
                evidence=w.evidence,
                mitre_keys=all_mitre_keys,
            )
        )

    sessions = sessionize(events)
    sess_dicts = [
        {
            "session_id": s.session_id,
            "user": s.user,
            "ip": s.ip,
            "start_ts": s.start_ts,
            "end_ts": s.end_ts,
            "events": s.events,
        }
        for s in sessions
    ]
    sb = sessions_to_sequences(sess_dicts, artifacts.token_map)
    if sb.x.shape[0] > 0:
        seq_s = score_seq_ae(seq_model, sb.x, sb.mask)
        for i, key in enumerate(sb.keys):
            user, ip, session_id = key
            s = sess_dicts[i]
            sequence_score = float(seq_s[i])
            if sequence_score < THRESHOLDS.signal_min_score:
                continue

            mitre_keys = _refine_mitre_from_evidence([], s["events"])
            if not mitre_keys:
                mitre_keys = ["valid_accounts"]

            detection_type, category, class_mitre_keys = classify_detection(
                None, s["events"], 0.0, sequence_score
            )
            all_mitre_keys = sorted(set(mitre_keys + class_mitre_keys))

            signals.append(
                Signal(
                    start_ts=s["start_ts"],
                    end_ts=s["end_ts"],
                    user=user,
                    ip=ip,
                    kind="sequence_anomaly",
                    score=sequence_score,
                    window_score=0.0,
                    sequence_score=sequence_score,
                    feature_vector=None,
                    feature_names=None,
                    evidence=s["events"],
                    mitre_keys=all_mitre_keys,
                )
            )

    rule_alerts = run_all_rules(events)
    
    for rule_alert in rule_alerts:
        matching_ml_score = 0.0
        for sig in signals:
            if sig.ip == rule_alert.entities.get("ip") or sig.user == rule_alert.entities.get("user"):
                matching_ml_score = max(matching_ml_score, sig.final_risk)
        
        if matching_ml_score > 0:
            final_score = 0.7 * rule_alert.confidence + 0.3 * matching_ml_score
        else:
            final_score = rule_alert.confidence
        
        signals.append(
            Signal(
                start_ts=rule_alert.start_ts,
                end_ts=rule_alert.end_ts,
                user=rule_alert.entities.get("user"),
                ip=rule_alert.entities.get("ip"),
                kind=f"rule_{rule_alert.rule_name}",
                score=final_score,
                window_score=matching_ml_score if matching_ml_score > 0 else 0.0,
                sequence_score=0.0,
                final_risk=final_score,
                detection_type=rule_alert.rule_name,
                category="rule_based",
                evidence=rule_alert.evidence,
                mitre_keys=[rule_alert.rule_name],
            )
        )
    
    alerts, incidents = correlate(signals, artifacts)
    return DetectionResult(signals=signals, alerts=alerts, incidents=incidents)


def detect_recent(events: List[Dict[str, Any]], artifacts: Artifacts, minutes: int = 360) -> DetectionResult:
    return detect(_recent(events, minutes=minutes), artifacts)


