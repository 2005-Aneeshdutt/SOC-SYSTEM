from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


LogSource = Literal["auth", "network", "process"]


class IngestRequest(BaseModel):
    source: LogSource
    events: List[Dict[str, Any]] = Field(min_length=1)


class Alert(BaseModel):
    alert_id: str
    created_ts: str
    start_ts: str
    end_ts: str
    user: Optional[str] = None
    ip: Optional[str] = None
    severity: Literal["low", "medium", "high"]
    score: float  # backward compat (final_risk)
    window_score: Optional[float] = None
    sequence_score: Optional[float] = None
    final_risk: Optional[float] = None
    detection_type: Optional[str] = None
    category: Optional[str] = None
    mitre: List[Dict[str, str]]
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    title: str
    explanation: str
    top_features: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    incident_id: Optional[int] = None


