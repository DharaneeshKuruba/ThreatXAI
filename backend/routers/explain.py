"""routers/explain.py — POST /explain/shap and /explain/lime endpoints"""

import json
import numpy as np
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.db.session import get_db
from backend.db.models import Alert
from backend.schemas import ExplainRequest, SHAPResponse, LIMEResponse, SHAPFeature, LIMEFeature
from backend.services.model_service import get_models, get_scaler, get_feature_names
from ..services.explain_service import get_shap_explanation, get_lime_explanation

router = APIRouter(prefix="/explain", tags=["Explainability"])

PROCESSED_DIR = None  # Lazy loaded


def _get_x_train():
    import os
    ml_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "ml")
    path = os.path.join(ml_dir, "data", "processed", "X_train.npy")
    if os.path.exists(path):
        return np.load(path)
    return None


@router.post("/shap", response_model=SHAPResponse)
async def explain_shap(req: ExplainRequest, db: Session = Depends(get_db)):
    models = get_models()
    if not models:
        raise HTTPException(503, "Models not loaded.")

    model_type = req.model_type if req.model_type in models else next(iter(models))
    model = models[model_type]
    scaler = get_scaler()
    feature_names = get_feature_names()

    features = np.array(req.features, dtype=np.float32)
    n_expected = scaler.mean_.shape[0]
    if len(features) < n_expected:
        features = np.pad(features, (0, n_expected - len(features)))
    features_scaled = scaler.transform(features.reshape(1, -1))[0]

    try:
        exp = get_shap_explanation(model, features_scaled, feature_names, model_type)
    except Exception as e:
        raise HTTPException(500, f"SHAP computation failed: {e}")

    if model_type == "dnn":
        proba = float(model.predict(features_scaled.reshape(1, -1), verbose=0).flatten()[0])
    else:
        proba = float(model.predict_proba(features_scaled.reshape(1, -1))[0][1])
    prediction = int(proba >= 0.5)

    # Persist SHAP result to alert if alert_id provided
    if req.alert_id:
        alert = db.query(Alert).filter(Alert.alert_id == req.alert_id).first()
        if alert:
            alert.shap_json = json.dumps(exp.get("shap_values", {}))
            db.commit()

    return SHAPResponse(
        alert_id=req.alert_id,
        shap_values=exp.get("shap_values", {}),
        top_features=[SHAPFeature(feature=f, shap_value=round(v, 6))
                      for f, v in exp.get("top_features", [])],
        prediction=prediction,
        confidence=round(proba, 4),
    )


@router.post("/lime", response_model=LIMEResponse)
async def explain_lime(req: ExplainRequest, db: Session = Depends(get_db)):
    models = get_models()
    if not models:
        raise HTTPException(503, "Models not loaded.")

    model_type = req.model_type if req.model_type in models else next(iter(models))
    model = models[model_type]
    scaler = get_scaler()
    feature_names = get_feature_names()

    features = np.array(req.features, dtype=np.float32)
    n_expected = scaler.mean_.shape[0]
    if len(features) < n_expected:
        features = np.pad(features, (0, n_expected - len(features)))
    features_scaled = scaler.transform(features.reshape(1, -1))[0]

    X_train = _get_x_train()
    if X_train is None:
        raise HTTPException(503, "Training data not found. Run preprocessing first.")

    try:
        exp = get_lime_explanation(model, features_scaled, X_train, feature_names, model_type)
    except Exception as e:
        raise HTTPException(500, f"LIME computation failed: {e}")

    # Persist
    if req.alert_id:
        alert = db.query(Alert).filter(Alert.alert_id == req.alert_id).first()
        if alert:
            alert.lime_json = json.dumps(exp.get("lime_features", []))
            db.commit()

    return LIMEResponse(
        alert_id=req.alert_id,
        lime_features=[LIMEFeature(feature=f["feature"], weight=f["weight"])
                       for f in exp.get("lime_features", [])],
        prediction_proba=exp.get("prediction_proba", [0.5, 0.5]),
    )


@router.get("/global/shap")
async def global_shap_importance(model_type: str = "xgboost"):
    """Returns global SHAP feature importance for a model."""
    import os
    models = get_models()
    if not models or model_type not in models:
        raise HTTPException(503, "Model not available.")

    model = models[model_type]
    feature_names = get_feature_names()

    ml_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "ml")
    x_test_path = os.path.join(ml_dir, "data", "processed", "X_test.npy")

    if not os.path.exists(x_test_path):
        raise HTTPException(503, "Test data not found.")

    X_test = np.load(x_test_path)
    from ..services.explain_service import get_global_shap
    importance = get_global_shap(model, X_test[:200], feature_names, model_type)

    return {
        "model": model_type,
        "feature_importance": [
            {"feature": f, "importance": round(v, 6)}
            for f, v in list(importance.items())[:30]
        ]
    }
