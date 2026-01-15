"""Evaluation metrics for detection models."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, roc_curve


def compute_detection_metrics(
    alerts: List[Dict[str, Any]],
    ground_truth: Dict[str, bool]  # alert_id -> is_attack (True/False)
) -> Dict[str, float]:
    """Compute precision, recall, F1-score for detection.
    
    Args:
        alerts: List of alert dictionaries with alert_id and final_risk
        ground_truth: Dictionary mapping alert_id to True (attack) or False (benign)
        
    Returns:
        Dictionary with precision, recall, f1, and support
    """
    if not alerts:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0}
    
    # Get predictions (threshold at 0.5)
    y_pred = [1 if a.get("final_risk", 0) >= 0.5 else 0 for a in alerts]
    y_true = [1 if ground_truth.get(a.get("alert_id"), False) else 0 for a in alerts]
    
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0.0
    )
    
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "support": int(support[1]) if len(support) > 1 else 0,
    }


def compute_roc_curve(
    alerts: List[Dict[str, Any]],
    ground_truth: Dict[str, bool]
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Compute ROC curve for anomaly scores.
    
    Args:
        alerts: List of alert dictionaries with final_risk
        ground_truth: Dictionary mapping alert_id to True (attack) or False (benign)
        
    Returns:
        fpr, tpr, thresholds arrays
    """
    if not alerts:
        return np.array([]), np.array([]), np.array([])
    
    scores = [a.get("final_risk", 0.0) for a in alerts]
    labels = [1 if ground_truth.get(a.get("alert_id"), False) else 0 for a in alerts]
    
    if len(set(labels)) < 2:  # Need both classes
        return np.array([]), np.array([]), np.array([])
    
    fpr, tpr, thresholds = roc_curve(labels, scores)
    return fpr, tpr, thresholds


def compute_auc_score(
    alerts: List[Dict[str, Any]],
    ground_truth: Dict[str, bool]
) -> float:
    """Compute AUC-ROC score.
    
    Args:
        alerts: List of alert dictionaries with final_risk
        ground_truth: Dictionary mapping alert_id to True (attack) or False (benign)
        
    Returns:
        AUC score (0.0 to 1.0)
    """
    if not alerts:
        return 0.0
    
    scores = [a.get("final_risk", 0.0) for a in alerts]
    labels = [1 if ground_truth.get(a.get("alert_id"), False) else 0 for a in alerts]
    
    if len(set(labels)) < 2:  # Need both classes
        return 0.0
    
    try:
        return float(roc_auc_score(labels, scores))
    except ValueError:
        return 0.0


def generate_synthetic_labels(alerts: List[Dict[str, Any]]) -> Dict[str, bool]:
    """Generate synthetic ground truth labels based on detection patterns.
    
    This is a heuristic: alerts with high risk and specific detection types
    are labeled as attacks.
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        Dictionary mapping alert_id to True (attack) or False (benign)
    """
    labels: Dict[str, bool] = {}
    
    attack_types = {
        "brute_force_login",
        "credential_stuffing",
        "lateral_movement_attempt",
        "exfil_spike",
        "bruteforce",
        "impossible_travel",
        "lateral_movement",
    }
    
    for alert in alerts:
        alert_id = alert.get("alert_id", "")
        final_risk = alert.get("final_risk", 0.0)
        detection_type = alert.get("detection_type", "")
        severity = alert.get("severity", "low")
        
        # Label as attack if:
        # - High risk (>0.7) OR
        # - Known attack type OR
        # - High severity
        is_attack = (
            final_risk > 0.7 or
            detection_type in attack_types or
            severity == "high"
        )
        
        labels[alert_id] = is_attack
    
    return labels

