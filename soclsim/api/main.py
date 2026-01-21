from __future__ import annotations

import os
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Depends
from sqlmodel import Session, select

from soclsim.logs.parsers import parse_any
from soclsim.logs.real_parsers import parse_real_log
from pathlib import Path
from soclsim.runtime.artifacts import Artifacts, load_artifacts
from soclsim.runtime.engine import detect_recent
from soclsim.runtime.state import STATE
from soclsim.schemas import Alert, IngestRequest
from soclsim.db import AlertRow, IncidentRow, init_db, get_session, upsert_alerts


def _get_artifacts_dir() -> str:
    return os.environ.get("SOCLSIM_ARTIFACTS_DIR", "artifacts")


def _load_or_raise() -> Artifacts:
    art_dir = _get_artifacts_dir()
    try:
        return load_artifacts(art_dir)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Artifacts not found. Train first: python -m soclsim.train --raw data/raw --artifacts {art_dir}",
        ) from e


app = FastAPI(title="AI-Powered SOC Log Intelligence System", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health(db: Session = Depends(get_session)) -> Dict[str, Any]:
    alerts_count = len(db.exec(select(AlertRow)).all())
    return {"ok": True, "events": len(STATE.events), "alerts": alerts_count}


@app.post("/ingest/logs")
def ingest(req: IngestRequest, db: Session = Depends(get_session)) -> Dict[str, Any]:
    try:
        arts = _load_or_raise()

        normalized: List[Dict[str, Any]] = []
        for raw in req.events:
            try:
                ne = parse_any(req.source, raw)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Bad event for source={req.source}: {e}") from e

            normalized.append(
                {
                    "ts": ne.ts,
                    "source": ne.source,
                    "event_type": ne.event_type,
                    "user": ne.user,
                    "ip": ne.ip,
                    "host": ne.host,
                    "fields": ne.fields,
                    "event_id": ne.event_id,
                }
            )

        STATE.events.extend(normalized)
        STATE.events = STATE.events[-250_000:]

        try:
            det = detect_recent(STATE.events, arts, minutes=360)
            if not det:
                return {"ingested": len(normalized), "new_alerts": 0}
            alerts_list = det.alerts if det.alerts else []
            incidents_list = det.incidents if det.incidents else []
            created = upsert_alerts(db, alerts_list, incidents_list)
        except Exception as e:
            import traceback
            error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            print(f"ERROR in detect/upsert: {error_detail}")
            raise HTTPException(status_code=500, detail=f"Detection/ingestion error: {error_detail}") from e

        return {"ingested": len(normalized), "new_alerts": created}
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        print(f"ERROR in ingest endpoint: {error_detail}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {error_detail}") from e


@app.post("/ingest/logs/file")
def ingest_log_file(
    file_path: str,
    db: Session = Depends(get_session)
) -> Dict[str, Any]:
    try:
        arts = _load_or_raise()
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
        
        from soclsim.logs.real_parsers import parse_real_log
        events = list(parse_real_log(file_path_obj))
        
        normalized: List[Dict[str, Any]] = []
        for ne in events:
            normalized.append(
                {
                    "ts": ne.ts,
                    "source": ne.source,
                    "event_type": ne.event_type,
                    "user": ne.user,
                    "ip": ne.ip,
                    "host": ne.host,
                    "fields": ne.fields,
                    "event_id": ne.event_id,
                }
            )
        
        STATE.events.extend(normalized)
        STATE.events = STATE.events[-250_000:]
        
        try:
            from soclsim.runtime.engine import detect_recent
            det = detect_recent(STATE.events, arts, minutes=360)
            if not det:
                return {"ingested": len(normalized), "new_alerts": 0}
            alerts_list = det.alerts if det.alerts else []
            incidents_list = det.incidents if det.incidents else []
            created = upsert_alerts(db, alerts_list, incidents_list)
        except Exception as e:
            import traceback
            error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            print(f"ERROR in detect/upsert: {error_detail}")
            raise HTTPException(status_code=500, detail=f"Detection/ingestion error: {error_detail}") from e
        
        return {"ingested": len(normalized), "new_alerts": created}
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=f"Unexpected error: {error_detail}") from e


@app.get("/alerts", response_model=List[Alert])
def get_alerts(
    min_severity: str = Query("low", pattern="^(low|medium|high)$"),
    limit: int = Query(100, ge=1, le=1000),
    user: Optional[str] = None,
    ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    order = {"low": 1, "medium": 2, "high": 3}
    min_rank = order[min_severity]

    with get_session() as db:
        stmt = select(AlertRow).order_by(AlertRow.created_ts.desc()).limit(5000)
        rows = db.exec(stmt).all()

    out: List[Dict[str, Any]] = []
    incident_id_map: Dict[int, str] = {}
    if rows:
        inc_ids = {r.incident_id for r in rows if r.incident_id}
        if inc_ids:
            inc_rows = db.exec(select(IncidentRow).where(IncidentRow.id.in_(inc_ids))).all()
            incident_id_map = {inc.id: inc.incident_id for inc in inc_rows}
    
    for r in rows:
        if order.get(r.severity, 1) < min_rank:
            continue
        if user and (r.user or "").lower() != user.lower():
            continue
        if ip and (r.ip or "") != ip:
            continue
        alert_dict = {
            "alert_id": r.alert_id,
            "created_ts": r.created_ts.isoformat().replace("+00:00", "Z"),
            "start_ts": r.start_ts.isoformat().replace("+00:00", "Z"),
            "end_ts": r.end_ts.isoformat().replace("+00:00", "Z"),
            "user": r.user,
            "ip": r.ip,
            "severity": r.severity,
            "score": r.final_risk,
            "window_score": r.window_score,
            "sequence_score": r.sequence_score,
            "final_risk": r.final_risk,
            "detection_type": r.detection_type,
            "category": r.category,
            "mitre": json.loads(r.mitre_json),
            "mitre_technique_id": r.mitre_technique_id,
            "mitre_tactic": r.mitre_tactic,
            "title": r.title,
            "explanation": r.explanation,
            "top_features": json.loads(r.top_features_json),
            "evidence": json.loads(r.evidence_json),
            "incident_id": r.incident_id,
        }
        if r.incident_id and r.incident_id in incident_id_map:
            alert_dict["incident_id_str"] = incident_id_map[r.incident_id]
        out.append(alert_dict)
        if len(out) >= limit:
            break
    return out


@app.get("/incidents")
def get_incidents(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_session),
) -> List[Dict[str, Any]]:
    stmt = select(IncidentRow).order_by(IncidentRow.end_ts.desc()).limit(limit)
    rows = db.exec(stmt).all()
    return [
        {
            "incident_id": r.incident_id,
            "start_ts": r.start_ts.isoformat().replace("+00:00", "Z"),
            "end_ts": r.end_ts.isoformat().replace("+00:00", "Z"),
            "primary_ip": r.primary_ip,
            "primary_user": r.primary_user,
            "total_alerts": r.total_alerts,
            "max_severity": r.max_severity,
            "categories": json.loads(r.categories_json),
            "entities": json.loads(r.entities_json),
            "summary": r.summary,
            "status": r.status,
            "analyst_notes": r.analyst_notes,
            "resolution_reason": r.resolution_reason,
        }
        for r in rows
    ]


@app.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    status: Optional[str] = None,
    analyst_notes: Optional[str] = None,
    resolution_reason: Optional[str] = None,
    db: Session = Depends(get_session)
) -> Dict[str, Any]:
    inc_row = db.exec(select(IncidentRow).where(IncidentRow.incident_id == incident_id)).first()
    if not inc_row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    if status:
        if status not in ["open", "investigating", "resolved", "false_positive"]:
            raise HTTPException(status_code=400, detail="Status must be one of: open, investigating, resolved, false_positive")
        inc_row.status = status
    
    if analyst_notes is not None:
        inc_row.analyst_notes = analyst_notes
    
    if resolution_reason is not None:
        inc_row.resolution_reason = resolution_reason
    
    db.add(inc_row)
    db.commit()
    db.refresh(inc_row)
    
    return {
        "incident_id": inc_row.incident_id,
        "status": inc_row.status,
        "analyst_notes": inc_row.analyst_notes,
        "resolution_reason": inc_row.resolution_reason,
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_session)) -> Dict[str, Any]:
    inc_row = db.exec(select(IncidentRow).where(IncidentRow.incident_id == incident_id)).first()
    
    if not inc_row:
        try:
            db_id = int(incident_id)
            inc_row = db.exec(select(IncidentRow).where(IncidentRow.id == db_id)).first()
        except ValueError:
            pass
    
    if not inc_row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    inc_db_id = inc_row.id
    alert_rows = db.exec(select(AlertRow).where(AlertRow.incident_id == inc_db_id)).all()
    alerts = [
        {
            "alert_id": r.alert_id,
            "created_ts": r.created_ts.isoformat().replace("+00:00", "Z"),
            "start_ts": r.start_ts.isoformat().replace("+00:00", "Z"),
            "end_ts": r.end_ts.isoformat().replace("+00:00", "Z"),
            "user": r.user,
            "ip": r.ip,
            "severity": r.severity,
            "final_risk": r.final_risk,
            "detection_type": r.detection_type,
            "category": r.category,
            "title": r.title,
        }
        for r in alert_rows
    ]

    return {
        "incident_id": inc_row.incident_id,
        "start_ts": inc_row.start_ts.isoformat().replace("+00:00", "Z"),
        "end_ts": inc_row.end_ts.isoformat().replace("+00:00", "Z"),
        "primary_ip": inc_row.primary_ip,
        "primary_user": inc_row.primary_user,
        "total_alerts": inc_row.total_alerts,
        "max_severity": inc_row.max_severity,
        "categories": json.loads(inc_row.categories_json),
        "entities": json.loads(inc_row.entities_json),
        "summary": inc_row.summary,
        "status": inc_row.status,
        "analyst_notes": inc_row.analyst_notes,
        "resolution_reason": inc_row.resolution_reason,
        "alerts": alerts,
    }


@app.get("/stats")
def stats() -> Dict[str, Any]:
    with get_session() as db:
        alert_rows = db.exec(select(AlertRow)).all()
    
    user_scores: Dict[str, Dict[str, Any]] = {}
    for r in alert_rows:
        if r.user:
            if r.user not in user_scores:
                user_scores[r.user] = {"max_score": 0.0, "incident_count": 0, "total_alerts": 0, "severity_weight": 0.0, "latest_ts": None}
            user_scores[r.user]["max_score"] = max(user_scores[r.user]["max_score"], r.final_risk)
            user_scores[r.user]["total_alerts"] += 1
            if r.incident_id:
                user_scores[r.user]["incident_count"] += 1
            sev_weight = {"high": 3.0, "medium": 2.0, "low": 1.0}.get(r.severity, 1.0)
            user_scores[r.user]["severity_weight"] += sev_weight
            if not user_scores[r.user]["latest_ts"] or r.created_ts > user_scores[r.user]["latest_ts"]:
                user_scores[r.user]["latest_ts"] = r.created_ts
    
    now = datetime.utcnow()
    user_risk_list = []
    for user, data in user_scores.items():
        recency_factor = 1.0
        if data["latest_ts"]:
            hours_ago = (now - data["latest_ts"]).total_seconds() / 3600
            recency_factor = max(0.5, 1.0 - (hours_ago / 168.0))
        
        weighted_risk = (
            data["max_score"] * 0.4 +
            min(data["incident_count"] / 10.0, 1.0) * 0.3 +
            min(data["severity_weight"] / 30.0, 1.0) * 0.2 +
            recency_factor * 0.1
        )
        user_risk_list.append({"user": user, "risk": round(weighted_risk, 3), "alerts": data["total_alerts"], "incidents": data["incident_count"]})
    
    ip_scores: Dict[str, Dict[str, Any]] = {}
    for r in alert_rows:
        if r.ip:
            if r.ip not in ip_scores:
                ip_scores[r.ip] = {"max_score": 0.0, "incident_count": 0, "total_alerts": 0, "severity_weight": 0.0, "latest_ts": None}
            ip_scores[r.ip]["max_score"] = max(ip_scores[r.ip]["max_score"], r.final_risk)
            ip_scores[r.ip]["total_alerts"] += 1
            if r.incident_id:
                ip_scores[r.ip]["incident_count"] += 1
            sev_weight = {"high": 3.0, "medium": 2.0, "low": 1.0}.get(r.severity, 1.0)
            ip_scores[r.ip]["severity_weight"] += sev_weight
            if not ip_scores[r.ip]["latest_ts"] or r.created_ts > ip_scores[r.ip]["latest_ts"]:
                ip_scores[r.ip]["latest_ts"] = r.created_ts
    
    ip_risk_list = []
    for ip, data in ip_scores.items():
        recency_factor = 1.0
        if data["latest_ts"]:
            hours_ago = (now - data["latest_ts"]).total_seconds() / 3600
            recency_factor = max(0.5, 1.0 - (hours_ago / 168.0))
        
        weighted_risk = (
            data["max_score"] * 0.4 +
            min(data["incident_count"] / 10.0, 1.0) * 0.3 +
            min(data["severity_weight"] / 30.0, 1.0) * 0.2 +
            recency_factor * 0.1
        )
        ip_risk_list.append({"ip": ip, "risk": round(weighted_risk, 3), "alerts": data["total_alerts"], "incidents": data["incident_count"]})
    
    return {
        "events": len(STATE.events),
        "alerts": len(alert_rows),
        "top_users": sorted(user_risk_list, key=lambda x: x["risk"], reverse=True)[:10],
        "top_ips": sorted(ip_risk_list, key=lambda x: x["risk"], reverse=True)[:10],
    }


