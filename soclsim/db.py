from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel, create_engine, Session, select

from soclsim.config import SETTINGS


class AlertRow(SQLModel, table=True):
    """Database-backed alert for long-term storage and aggregation."""

    id: Optional[int] = Field(default=None, primary_key=True)
    alert_id: str = Field(index=True, unique=True)
    created_ts: datetime = Field(index=True)
    start_ts: datetime
    end_ts: datetime
    user: Optional[str] = Field(default=None, index=True)
    ip: Optional[str] = Field(default=None, index=True)
    severity: str = Field(index=True)
    score: float  # final_risk (kept for backward compat)
    window_score: float
    sequence_score: float
    final_risk: float = Field(index=True)
    detection_type: str = Field(index=True)  # bruteforce, port_scan, lateral_movement, exfil_spike, service_acct_abuse
    category: str = Field(index=True)  # authentication, network_recon, lateral_movement, exfiltration, privilege_misuse
    title: str
    explanation: str
    mitre_json: str
    mitre_technique_id: Optional[str] = Field(default=None, index=True)
    mitre_tactic: Optional[str] = Field(default=None)
    top_features_json: str
    evidence_json: str
    incident_id: Optional[int] = Field(default=None, foreign_key="incidentrow.id", index=True)


class IncidentRow(SQLModel, table=True):
    """Incident grouping multiple correlated alerts."""

    id: Optional[int] = Field(default=None, primary_key=True)
    incident_id: str = Field(index=True, unique=True)
    start_ts: datetime = Field(index=True)
    end_ts: datetime = Field(index=True)
    primary_ip: Optional[str] = Field(default=None, index=True)
    primary_user: Optional[str] = Field(default=None, index=True)
    total_alerts: int
    max_severity: str = Field(index=True)
    categories_json: str  # JSON list of detection_type/category counts
    entities_json: str  # JSON of IPs/users involved
    summary: str
    status: str = Field(default="open")  # open, investigating, resolved, false_positive
    analyst_notes: str = Field(default="")
    resolution_reason: str = Field(default="")


engine = create_engine("sqlite:///./soc_alerts.db", echo=False, future=True)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)


def upsert_alerts(session: Session, alerts: list[dict], incidents: list[dict] | None = None) -> int:
    """Insert new alerts and incidents; skip ones we already have by alert_id/incident_id."""
    if incidents is None:
        incidents = []
    """Insert new alerts and incidents; skip ones we already have by alert_id/incident_id."""
    if not alerts:
        return 0

    # Upsert incidents first if provided
    incident_id_map: dict[str, int] = {}
    if incidents and len(incidents) > 0:
        try:
            existing_inc_ids = {
                row.incident_id
                for row in session.exec(
                    select(IncidentRow.incident_id).where(IncidentRow.incident_id.in_([inc["incident_id"] for inc in incidents]))
                )
            }
            for inc in incidents:
                if inc["incident_id"] in existing_inc_ids:
                    # Get existing ID
                    existing = session.exec(select(IncidentRow).where(IncidentRow.incident_id == inc["incident_id"])).first()
                    if existing:
                        incident_id_map[inc["incident_id"]] = existing.id
                    continue
                row = IncidentRow(
                    incident_id=inc["incident_id"],
                    start_ts=datetime.fromisoformat(inc["start_ts"].replace("Z", "+00:00")),
                    end_ts=datetime.fromisoformat(inc["end_ts"].replace("Z", "+00:00")),
                    primary_ip=inc.get("primary_ip"),
                    primary_user=inc.get("primary_user"),
                    total_alerts=inc["total_alerts"],
                    max_severity=inc["max_severity"],
                    categories_json=json.dumps(inc.get("categories", {})),
                    entities_json=json.dumps(inc.get("entities", {})),
                    summary=inc["summary"],
                    status=inc.get("status", "open"),
                    analyst_notes=inc.get("analyst_notes", ""),
                    resolution_reason=inc.get("resolution_reason", ""),
                )
                session.add(row)
                session.flush()  # Get the ID
                incident_id_map[inc["incident_id"]] = row.id
            if incidents:
                session.commit()
        except Exception as e:
            session.rollback()
            raise RuntimeError(f"Failed to upsert incidents: {e}") from e

    existing_ids = {
        row.alert_id
        for row in session.exec(
            select(AlertRow.alert_id).where(AlertRow.alert_id.in_([a["alert_id"] for a in alerts]))
        )
    }
    created = 0
    for a in alerts:
        if a["alert_id"] in existing_ids:
            continue

        # Get incident_id if provided
        incident_db_id = None
        if a.get("incident_id"):
            incident_db_id = incident_id_map.get(a["incident_id"])
            # If incident_id not found in map, try to look it up in DB
            if incident_db_id is None:
                existing_inc = session.exec(select(IncidentRow).where(IncidentRow.incident_id == a["incident_id"])).first()
                if existing_inc:
                    incident_db_id = existing_inc.id

        # Extract MITRE technique/tactic from mitre list
        mitre_list = a.get("mitre", [])
        mitre_technique_id = None
        mitre_tactic = None
        if mitre_list and isinstance(mitre_list, list) and len(mitre_list) > 0:
            mitre_technique_id = mitre_list[0].get("technique_id")
            mitre_tactic = mitre_list[0].get("tactic")

        row = AlertRow(
            alert_id=a["alert_id"],
            created_ts=datetime.fromisoformat(a["created_ts"].replace("Z", "+00:00")),
            start_ts=datetime.fromisoformat(a["start_ts"].replace("Z", "+00:00")),
            end_ts=datetime.fromisoformat(a["end_ts"].replace("Z", "+00:00")),
            user=a.get("user"),
            ip=a.get("ip"),
            severity=a["severity"],
            score=a.get("final_risk", a.get("score", 0.0)),  # backward compat
            window_score=a.get("window_score", 0.0),
            sequence_score=a.get("sequence_score", 0.0),
            final_risk=a.get("final_risk", a.get("score", 0.0)),
            detection_type=a.get("detection_type", "unknown"),
            category=a.get("category", "unknown"),
            title=a["title"],
            explanation=a["explanation"],
            mitre_json=json.dumps(mitre_list),
            mitre_technique_id=mitre_technique_id,
            mitre_tactic=mitre_tactic,
            top_features_json=json.dumps(a.get("top_features", [])),
            evidence_json=json.dumps(a.get("evidence", [])),
            incident_id=incident_db_id,
        )
        session.add(row)
        created += 1
    if created:
        session.commit()
    return created


