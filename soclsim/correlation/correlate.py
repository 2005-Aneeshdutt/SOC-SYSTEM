from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from soclsim.config import SETTINGS
from soclsim.config import THRESHOLDS
from soclsim.correlation.mitre import mitre_for_keys
from soclsim.models.scoring import explain_top_features
from soclsim.utils.time import parse_ts, to_iso_utc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soclsim.runtime.artifacts import Artifacts


@dataclass(frozen=True)
class Signal:
    start_ts: str
    end_ts: str
    user: Optional[str]
    ip: Optional[str]
    kind: str
    score: float
    window_score: float = 0.0  # Window anomaly score (ISO + dense AE)
    sequence_score: float = 0.0  # Sequence anomaly score (LSTM AE)
    final_risk: float = 0.0
    detection_type: str = "unknown"
    category: str = "unknown"
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    feature_vector: Optional[List[float]] = None
    feature_names: Optional[List[str]] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    mitre_keys: Optional[List[str]] = None


def _severity(score: float) -> str:
    if score >= THRESHOLDS.severity_high:
        return "high"
    if score >= THRESHOLDS.severity_medium:
        return "medium"

    return "low"


def _combine_scores(scores: List[float]) -> float:
    """Fuse multiple signal scores into one incident score.

    Strategy:
    - Bound each signal into [0, 1]
    - Combine using a simple blend of max and mean so we preserve both
      the strongest signal and overall anomaly level.
    This avoids everything saturating at 1 while still ranking truly
    bad incidents higher.
    """
    if not scores:
        return 0.0
    bounded = [float(max(0.0, min(1.0, s))) for s in scores]

    avg = sum(bounded) / len(bounded)
    mx = max(bounded)
    return float(0.5 * mx + 0.5 * avg)


def correlate(signals: List[Signal], artifacts: "Artifacts | None" = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Combine multiple weak signals into incidents, keyed by entity (user OR IP) and time.
    
    Returns:
        (alerts, incidents) - alerts with incident_id, and incident summaries
    """
    if not signals:
        return [], []

    signals = sorted(signals, key=lambda s: s.start_ts)
    win = timedelta(minutes=SETTINGS.correlation_window_minutes)

    alerts: List[Dict[str, Any]] = []
    incidents: List[Dict[str, Any]] = []
    
    # Group signals by entity (user OR IP) and time window
    # entity_key -> list of signals in that incident
    entity_incidents: Dict[str, List[Signal]] = {}
    
    def get_entity_key(signal: Signal) -> Optional[str]:
        """Get entity key for grouping: prefer user, fallback to IP."""
        if signal.user:
            return f"user:{signal.user}"
        elif signal.ip:
            return f"ip:{signal.ip}"
        return None
    
    # First pass: group signals by entity and time window
    for signal in signals:
        entity_key = get_entity_key(signal)
        if not entity_key:
            # Skip signals without entity
            continue
        
        signal_start = parse_ts(signal.start_ts)
        signal_end = parse_ts(signal.end_ts)
        
        # Check if this signal belongs to an existing incident for this entity
        matched_incident = None
        for key, sigs in entity_incidents.items():
            if key == entity_key:
                # Check if signal is within time window of existing incident
                last_signal_end = max(parse_ts(s.end_ts) for s in sigs)
                if signal_start <= (last_signal_end + win):
                    matched_incident = key
                    break
        
        if matched_incident:
            # Add to existing incident
            entity_incidents[matched_incident].append(signal)
        else:
            # Create new incident group
            entity_incidents[entity_key] = [signal]
    
    # Second pass: create incidents and alerts from grouped signals
    for entity_key, sigs in entity_incidents.items():
        if len(sigs) < SETTINGS.incident_min_signals:
            continue
        
        # Sort signals by time
        sigs = sorted(sigs, key=lambda s: s.start_ts)
        
        # Compute combined scores
        scores = [s.score for s in sigs]
        window_scores = [s.window_score for s in sigs if s.window_score > 0]
        sequence_scores = [s.sequence_score for s in sigs if s.sequence_score > 0]
        
        # Final risk: weighted combination
        avg_window = sum(window_scores) / len(window_scores) if window_scores else 0.0
        avg_sequence = sum(sequence_scores) / len(sequence_scores) if sequence_scores else 0.0
        final_risk = float(0.6 * avg_window + 0.4 * avg_sequence) if (window_scores or sequence_scores) else _combine_scores(scores)
        
        sev = _severity(final_risk)
        
        start_dt = min(parse_ts(s.start_ts) for s in sigs)
        end_dt = max(parse_ts(s.end_ts) for s in sigs)
        
        # Extract primary entity
        primary_user = sigs[0].user if sigs[0].user else None
        primary_ip = sigs[0].ip if sigs[0].ip else None
        
        mitre_keys: List[str] = []
        evidence: List[Dict[str, Any]] = []
        top_features: List[Dict[str, Any]] = []
        detection_types: List[str] = []
        categories: List[str] = []
        
        for s in sigs:
            if s.mitre_keys:
                mitre_keys.extend(s.mitre_keys)
            if s.evidence:
                evidence.extend(s.evidence)  # Include ALL evidence
            if s.feature_vector is not None and s.feature_names is not None:
                import numpy as np
                feature_stats = artifacts.feature_stats if artifacts else None
                top_features.extend(explain_top_features(
                    np.array(s.feature_vector, dtype=np.float32), 
                    s.feature_names, 
                    k=3,
                    feature_stats=feature_stats
                ))
            if s.detection_type:
                detection_types.append(s.detection_type)
            if s.category:
                categories.append(s.category)
        
        # Dedupe feature list
        tf_seen = set()
        tf_d = []
        for t in sorted(top_features, key=lambda d: -float(d.get("attribution", d.get("z_score", 0)))):
            k = t["feature"]
            if k in tf_seen:
                continue
            tf_seen.add(k)
            tf_d.append(t)
            if len(tf_d) >= 5:
                break
        
        mitre = mitre_for_keys(sorted(set(mitre_keys)))
        
        # Classify detection from signals
        from soclsim.detection.classify import classify_detection, get_detection_title
        
        # Aggregate window features if available
        window_feat_dict = None
        for s in sigs:
            if s.feature_vector and s.feature_names:
                window_feat_dict = {name: float(s.feature_vector[i]) for i, name in enumerate(s.feature_names)}
                break
        
        detection_type, category, class_mitre_keys = classify_detection(
            window_feat_dict, evidence, avg_window, avg_sequence
        )
        all_mitre = mitre_for_keys(sorted(set(mitre_keys + class_mitre_keys)))
        
        incident_id = f"inc_{uuid.uuid4().hex[:12]}"
        explanation = _render_explanation(sigs, final_risk, sev, all_mitre)
        title = get_detection_title(detection_type, sev, primary_user, primary_ip)
        
        # Build incident summary
        entities = {"ips": set(), "users": set()}
        for s in sigs:
            if s.ip:
                entities["ips"].add(s.ip)
            if s.user:
                entities["users"].add(s.user)
        
        categories_count: Dict[str, int] = {}
        for cat in categories:
            categories_count[cat] = categories_count.get(cat, 0) + 1
        
        incident_summary = {
            "incident_id": incident_id,
            "start_ts": to_iso_utc(start_dt),
            "end_ts": to_iso_utc(end_dt),
            "primary_ip": primary_ip,
            "primary_user": primary_user,
            "total_alerts": len(sigs),
            "max_severity": sev,
            "categories": categories_count,
            "entities": {
                "ips": list(entities["ips"]),
                "users": list(entities["users"]),
            },
            "summary": f"{detection_type.replace('_', ' ').title()} incident affecting {primary_ip or primary_user or 'unknown entity'}",
            "status": "open",
            "analyst_notes": "",
            "resolution_reason": "",
        }
        incidents.append(incident_summary)
        
        # Create alert for this incident
        alerts.append(
            {
                "alert_id": f"al_{uuid.uuid4().hex[:12]}",
                "created_ts": to_iso_utc(datetime.utcnow().replace(tzinfo=None)),
                "start_ts": to_iso_utc(start_dt),
                "end_ts": to_iso_utc(end_dt),
                "user": primary_user,
                "ip": primary_ip,
                "severity": sev,
                "score": float(final_risk),  # backward compat
                "window_score": float(avg_window),
                "sequence_score": float(avg_sequence),
                "final_risk": float(final_risk),
                "detection_type": detection_type,
                "category": category,
                "mitre": all_mitre,
                "mitre_technique_id": all_mitre[0]["technique_id"] if all_mitre else None,
                "mitre_tactic": all_mitre[0]["tactic"] if all_mitre else None,
                "title": title,
                "explanation": explanation,
                "top_features": tf_d,
                "evidence": evidence,  # Include ALL events
                "incident_id": incident_id,
            }
        )
    
    # Re-label severities using quantiles so that distribution always has a mix
    # of low / medium / high, which is closer to what SOC analysts expect to see.
    if not alerts:
        return alerts, incidents

    import numpy as np

    scores = np.array([a["final_risk"] for a in alerts], dtype=np.float32)
    
    # Soften scores using logistic scaling to avoid saturation
    # Apply percentile-based normalization with logistic transform for natural distribution
    if len(scores) >= 3:
        # First, normalize to [0, 1] using percentiles
        p5, p95 = float(np.quantile(scores, 0.05)), float(np.quantile(scores, 0.95))
        if p95 > p5:
            # Normalize to [0, 1] range
            normalized = (scores - p5) / (p95 - p5)
            normalized = np.clip(normalized, 0.0, 1.0)
        else:
            normalized = scores / (np.max(scores) + 1e-6) if np.max(scores) > 0 else scores
        
        # Apply logistic scaling: maps [0, 1] to [0.4, 0.95] with natural curve
        # Formula: 0.4 + 0.55 * (1 / (1 + exp(-k*(x - 0.5))))
        # k controls steepness, we use k=4 for smooth distribution
        k = 4.0
        logistic_scaled = 0.4 + 0.55 / (1.0 + np.exp(-k * (normalized - 0.5)))
        
        # Update final_risk with logistic-scaled scores
        for i, a in enumerate(alerts):
            a["final_risk"] = float(logistic_scaled[i])
            scores[i] = logistic_scaled[i]
        
        q60 = float(np.quantile(scores, 0.6))
        q90 = float(np.quantile(scores, 0.9))
    else:
        # Fallback: logistic scaling on raw scores
        q60 = THRESHOLDS.severity_medium
        q90 = THRESHOLDS.severity_high
        for a in alerts:
            raw_score = float(a["final_risk"])
            # Apply logistic transform: 0.4 + 0.55 * sigmoid(4*(x - 0.5))
            logistic_score = 0.4 + 0.55 / (1.0 + math.exp(-4.0 * (raw_score - 0.5)))
            a["final_risk"] = float(min(0.95, logistic_score))

    for a in alerts:
        s = float(a["final_risk"])
        if s >= q90:
            a["severity"] = "high"
        elif s >= q60:
            a["severity"] = "medium"
        else:
            a["severity"] = "low"

    # Update incident max_severity based on alerts
    for inc in incidents:
        inc_alerts = [a for a in alerts if a.get("incident_id") == inc["incident_id"]]
        if inc_alerts:
            sev_rank = {"low": 1, "medium": 2, "high": 3}
            inc["max_severity"] = max(inc_alerts, key=lambda a: sev_rank.get(a["severity"], 0))["severity"]
    
    # Final deduplication pass: merge incidents with same entity and overlapping time windows
    if len(incidents) > 1:
        dedup_window = timedelta(minutes=SETTINGS.correlation_window_minutes)
        merged_incidents: List[Dict[str, Any]] = []
        merged_alert_map: Dict[str, str] = {}  # old_incident_id -> new_incident_id
        
        # Sort by start time
        incidents_sorted = sorted(incidents, key=lambda inc: parse_ts(inc["start_ts"]))
        
        for inc in incidents_sorted:
            merged = False
            inc_start = parse_ts(inc["start_ts"])
            inc_ip = inc.get("primary_ip")
            inc_user = inc.get("primary_user")
            
            # Check if this incident should merge with an existing one
            for existing in merged_incidents:
                existing_start = parse_ts(existing["start_ts"])
                existing_end = parse_ts(existing["end_ts"])
                existing_ip = existing.get("primary_ip")
                existing_user = existing.get("primary_user")
                
                # Same IP OR same user (not both required), and time windows overlap or are close
                time_diff = abs((inc_start - existing_end).total_seconds())
                same_entity = (inc_ip and inc_ip == existing_ip) or (inc_user and inc_user == existing_user)
                
                if same_entity and time_diff < dedup_window.total_seconds():
                    # Merge: update existing incident
                    existing["end_ts"] = max(existing_end, parse_ts(inc["end_ts"])).isoformat().replace("+00:00", "Z")
                    existing["total_alerts"] += inc["total_alerts"]
                    existing["max_severity"] = max(
                        existing["max_severity"], inc["max_severity"],
                        key=lambda s: {"low": 1, "medium": 2, "high": 3}.get(s, 0)
                    )
                    # Merge categories
                    existing_cats = existing.get("categories", {})
                    inc_cats = inc.get("categories", {})
                    for k, v in inc_cats.items():
                        existing_cats[k] = existing_cats.get(k, 0) + v
                    existing["categories"] = existing_cats
                    # Merge entities
                    existing_ents = existing.get("entities", {})
                    inc_ents = inc.get("entities", {})
                    for k in ["ips", "users"]:
                        existing_ents[k] = list(set(existing_ents.get(k, []) + inc_ents.get(k, [])))
                    existing["entities"] = existing_ents
                    existing["summary"] = f"Merged: {existing.get('summary', '')} + {inc.get('summary', '')}"
                    
                    # Map old incident_id to new one
                    merged_alert_map[inc["incident_id"]] = existing["incident_id"]
                    merged = True
                    break
            
            if not merged:
                merged_incidents.append(inc)
        
        # Update alert incident_ids
        for a in alerts:
            if a.get("incident_id") in merged_alert_map:
                a["incident_id"] = merged_alert_map[a["incident_id"]]
        
        incidents = merged_incidents

    return alerts, incidents


def _render_title(signals: List[Signal], sev: str) -> str:
    kinds = sorted({s.kind for s in signals})
    base = " + ".join(kinds[:3])
    return f"{sev.upper()} incident: {base}"


def _render_explanation(signals: List[Signal], score: float, sev: str, mitre: List[Dict[str, str]]) -> str:
    n = len(signals)
    kinds = sorted({s.kind for s in signals})
    kind_str = ", ".join(kinds[:3])
    mitre_str = "\n".join([f"- {m['technique_id']} {m['technique']} ({m['tactic']})" for m in mitre[:3]])
    return f"Correlated {n} anomalous signals into a {sev.upper()} incident (score={score:.2f}).\nTop contributing signals:\n- {kind_str}\nMapped to MITRE ATT&CK:\n{mitre_str}"
