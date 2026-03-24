"""routers/alerts.py — GET /alerts, GET /alerts/{alert_id}, DELETE /alerts"""

import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from backend.db.session import get_db
from backend.db.models import Alert
from backend.schemas import AlertOut, SHAPFeature

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# ─── Configuration ─────────────────────────────────────────────────────────────
MAX_ALERTS = 500  # Maximum alerts to keep in DB. Oldest benign alerts purged first.


def _enforce_alert_cap(db: Session):
    """Purge oldest alerts when DB exceeds MAX_ALERTS. Benign alerts purged first."""
    total = db.query(func.count(Alert.id)).scalar()
    if total <= MAX_ALERTS:
        return

    excess = total - MAX_ALERTS

    # Phase 1: delete oldest benign alerts
    benign_ids = (
        db.query(Alert.id)
        .filter(Alert.prediction == 0)
        .order_by(Alert.timestamp.asc())
        .limit(excess)
        .all()
    )
    benign_to_delete = [row[0] for row in benign_ids]
    if benign_to_delete:
        db.query(Alert).filter(Alert.id.in_(benign_to_delete)).delete(synchronize_session=False)
        db.commit()
        excess -= len(benign_to_delete)

    # Phase 2: if still over cap, delete oldest attack alerts
    if excess > 0:
        attack_ids = (
            db.query(Alert.id)
            .filter(Alert.prediction == 1)
            .order_by(Alert.timestamp.asc())
            .limit(excess)
            .all()
        )
        attack_to_delete = [row[0] for row in attack_ids]
        if attack_to_delete:
            db.query(Alert).filter(Alert.id.in_(attack_to_delete)).delete(synchronize_session=False)
            db.commit()


@router.get("", response_model=List[dict])
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=200),
    prediction: Optional[int] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Alert).order_by(Alert.timestamp.desc())
    if prediction is not None:
        query = query.filter(Alert.prediction == prediction)
    alerts = query.offset(skip).limit(limit).all()

    result = []
    for row_num, a in enumerate(alerts, start=skip + 1):
        shap_features = []
        if a.shap_json:
            try:
                shap_dict = json.loads(a.shap_json)
                sorted_feats = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)
                shap_features = [{"feature": f, "shap_value": round(v, 6)} for f, v in sorted_feats[:10]]
            except Exception:
                pass

        result.append({
            "id": a.id,
            "row_number": row_num,  # Sequential display number (1, 2, 3...)
            "alert_id": a.alert_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "protocol": a.protocol,
            "prediction": a.prediction,
            "label": a.label,
            "confidence": a.confidence,
            "cluster_id": a.cluster_id,
            "cluster_label": a.cluster_label,
            "cluster_similarity": a.cluster_similarity,
            "shap_top_features": shap_features,
            "is_live_capture": a.is_live_capture,
        })
    return result


@router.get("/stats/summary")
async def alert_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Alert.id)).scalar()
    attacks = db.query(func.count(Alert.id)).filter(Alert.prediction == 1).scalar()
    benign = total - attacks
    clusters = db.query(func.count(Alert.cluster_id.distinct())).filter(
        Alert.cluster_id.isnot(None)
    ).scalar()
    return {
        "total_alerts": total,
        "attacks": attacks,
        "benign": benign,
        "unique_clusters": clusters,
        "attack_rate": round(attacks / total, 3) if total > 0 else 0,
        "max_alerts": MAX_ALERTS,
        "storage_usage": f"{total}/{MAX_ALERTS}",
    }


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(404, f"Alert {alert_id} not found")

    shap_data = {}
    lime_data = []
    if alert.shap_json:
        try:
            shap_dict = json.loads(alert.shap_json)
            shap_data = {
                "shap_values": shap_dict,
                "top_features": sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:15],
            }
        except Exception:
            pass
    if alert.lime_json:
        try:
            lime_data = json.loads(alert.lime_json)
        except Exception:
            pass

    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "protocol": alert.protocol,
        "prediction": alert.prediction,
        "label": alert.label,
        "confidence": alert.confidence,
        "cluster_id": alert.cluster_id,
        "cluster_label": alert.cluster_label,
        "cluster_similarity": alert.cluster_similarity,
        "shap": shap_data,
        "lime": lime_data,
        "features": json.loads(alert.features_json) if alert.features_json else [],
    }


@router.delete("/{alert_id}")
async def delete_alert(alert_id: str, db: Session = Depends(get_db)):
    """Delete a specific alert by alert_id."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(404, f"Alert {alert_id} not found")

    cluster_id = alert.cluster_id
    db.delete(alert)
    db.commit()

    # Return updated count
    remaining = db.query(func.count(Alert.id)).scalar()
    return {
        "status": "deleted",
        "alert_id": alert_id,
        "cluster_id": cluster_id,
        "remaining_alerts": remaining,
    }


@router.delete("")
async def delete_all_alerts(
    prediction: Optional[int] = Query(None, description="Filter: 0=benign, 1=attack, None=all"),
    db: Session = Depends(get_db)
):
    """Delete all alerts, optionally filtered by prediction type."""
    query = db.query(Alert)
    if prediction is not None:
        query = query.filter(Alert.prediction == prediction)

    count = query.count()
    query.delete(synchronize_session=False)
    db.commit()

    return {
        "status": "deleted",
        "count": count,
        "filter": f"prediction={prediction}" if prediction is not None else "all",
        "remaining_alerts": db.query(func.count(Alert.id)).scalar(),
    }
