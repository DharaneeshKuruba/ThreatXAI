"""routers/clusters.py — GET /clusters (EDAC novel endpoint)"""

import json
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.db.session import get_db
from backend.db.models import Alert
from backend.services.model_service import get_edac_engine

router = APIRouter(prefix="/clusters", tags=["EDAC Clusters"])


def _clusters_from_db(db: Session) -> list:
    """
    Build cluster summaries from stored alerts when the in-memory
    EDAC engine has no clusters (e.g. after backend restart).
    Groups alerts by cluster_id and reconstructs campaign info.
    """
    rows = (
        db.query(
            Alert.cluster_id,
            Alert.cluster_label,
            func.count(Alert.id).label("member_count"),
            func.avg(Alert.cluster_similarity).label("avg_similarity"),
            func.group_concat(Alert.alert_id).label("alert_ids"),
        )
        .filter(Alert.cluster_id.isnot(None))
        .group_by(Alert.cluster_id)
        .all()
    )
    clusters = []
    for row in rows:
        alert_ids = [a.strip() for a in (row.alert_ids or "").split(",") if a.strip()]

        # Get top SHAP features from the first alert in this cluster
        top_features = []
        try:
            sample_alert = (
                db.query(Alert.shap_json)
                .filter(Alert.cluster_id == row.cluster_id, Alert.shap_json.isnot(None))
                .first()
            )
            if sample_alert and sample_alert.shap_json:
                shap_data = json.loads(sample_alert.shap_json)
                sorted_feats = sorted(
                    shap_data.items(), key=lambda x: abs(float(x[1])), reverse=True
                )[:10]
                top_features = [
                    {"feature": f, "shap_value": round(float(v), 6)}
                    for f, v in sorted_feats
                ]
        except Exception:
            pass

        clusters.append({
            "cluster_id": row.cluster_id,
            "label": row.cluster_label or "Unknown Campaign",
            "member_count": row.member_count,
            "avg_similarity": round(float(row.avg_similarity or 0), 4),
            "alert_ids": alert_ids[-20:],
            "top_shap_features": top_features,
            "centroid": [],
        })
    return clusters


@router.get("")
async def get_all_clusters(db: Session = Depends(get_db)):
    """Returns all EDAC clusters with semantic attack labels and top SHAP features."""
    try:
        edac = get_edac_engine()
        clusters = edac.get_all_clusters()
        if clusters:
            clusters.sort(key=lambda x: x["member_count"], reverse=True)
            return {"count": len(clusters), "clusters": clusters}
    except Exception:
        pass

    # Fallback: reconstruct from database alerts
    clusters = _clusters_from_db(db)
    clusters.sort(key=lambda x: x["member_count"], reverse=True)
    return {
        "count": len(clusters),
        "clusters": clusters,
        "source": "database",
    }


@router.get("/stats/summary")
async def cluster_stats(db: Session = Depends(get_db)):
    # Try in-memory first
    clusters = []
    try:
        edac = get_edac_engine()
        clusters = edac.get_all_clusters()
    except Exception:
        pass

    # Fallback to DB
    if not clusters:
        clusters = _clusters_from_db(db)

    total_alerts = sum(c["member_count"] for c in clusters)
    label_counts = {}
    for c in clusters:
        label_counts[c["label"]] = label_counts.get(c["label"], 0) + c["member_count"]
    return {
        "total_clusters": len(clusters),
        "total_alerts_clustered": total_alerts,
        "attack_campaign_breakdown": label_counts,
        "largest_cluster": max(clusters, key=lambda x: x["member_count"]) if clusters else None,
    }


@router.get("/{cluster_id}")
async def get_cluster(cluster_id: str, db: Session = Depends(get_db)):
    # Try in-memory first
    try:
        edac = get_edac_engine()
        cluster = edac.get_cluster(cluster_id)
        if cluster:
            return cluster
    except Exception:
        pass

    # Fallback to DB
    clusters = _clusters_from_db(db)
    for c in clusters:
        if c["cluster_id"] == cluster_id:
            return c
    raise HTTPException(404, f"Cluster {cluster_id} not found")
