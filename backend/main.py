"""main.py — ThreatXAI FastAPI Application Entry Point"""

import os
import sys
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Add backend directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: load models and create DB tables."""
    log.info("★ ThreatXAI API starting...")
    try:
        from backend.db.session import engine
        from backend.db import models
        models.Base.metadata.create_all(bind=engine)
        log.info("✓ Database tables created")
    except Exception as e:
        log.error(f"Database setup failed: {e}")
    
    # Apply persistent config
    try:
        from backend.services import capture_service
        capture_service._default_model = _app_config.get("default_model", "xgboost")
        
        from backend.services.model_service import get_edac_engine
        edac = get_edac_engine()
        if edac:
            edac.SIMILARITY_THRESHOLD = float(_app_config.get("edac_similarity_threshold", 0.80))
        log.info("✓ Persistent configuration applied")
    except Exception as e:
        log.error(f"Failed to apply config: {e}")

    log.info("★ ThreatXAI API ready")
    yield
    log.info("ThreatXAI API shutting down")


app = FastAPI(
    title="ThreatXAI API",
    description=(
        "Explainable Intrusion Detection System with SHAP, LIME, and "
        "Explanation-Driven Alert Clustering (EDAC)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
from backend.routers import predict, explain, alerts, capture, clusters

app.include_router(predict.router)
app.include_router(explain.router)
app.include_router(alerts.router)
app.include_router(capture.router)
app.include_router(clusters.router)


@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "ThreatXAI API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "novel_feature": "Explanation-Driven Alert Clustering (EDAC)",
    }


@app.get("/health", tags=["Health"])
async def health():
    from backend.services.model_service import get_models
    models = get_models()
    return {
        "status": "healthy",
        "models_loaded": list(models.keys()),
        "model_count": len(models),
    }


@app.get("/metrics", tags=["Model Performance"])
async def model_metrics():
    from backend.services.model_service import get_metrics
    return {"metrics": get_metrics()}


# ─── Runtime Configuration ─────────────────────────────────────────────────────
import json

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_app_config = {
    "default_model": "xgboost",
    "edac_similarity_threshold": 0.80,
    "max_alerts": 500,
}

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r") as f:
            _app_config.update(json.load(f))
    except Exception as e:
        log.error(f"Failed to load config from JSON: {e}")

def _save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(_app_config, f, indent=4)
    except Exception as e:
        log.error(f"Failed to save config to JSON: {e}")


@app.get("/config", tags=["Configuration"])
async def get_config():
    return _app_config


@app.post("/config", tags=["Configuration"])
async def update_config(updates: dict):
    changed = {}
    if "default_model" in updates:
        valid_models = ["xgboost", "rf", "dnn"]
        model = updates["default_model"].lower()
        if model in valid_models:
            _app_config["default_model"] = model
            from backend.services import capture_service
            capture_service._default_model = model
            changed["default_model"] = model
    if "edac_similarity_threshold" in updates:
        thresh = float(updates["edac_similarity_threshold"])
        thresh = max(0.5, min(0.99, thresh))
        _app_config["edac_similarity_threshold"] = thresh
        try:
            from backend.services.model_service import get_edac_engine
            edac = get_edac_engine()
            if edac:
                edac.SIMILARITY_THRESHOLD = thresh
        except Exception:
            pass
        changed["edac_similarity_threshold"] = thresh
    if "max_alerts" in updates:
        cap = int(updates["max_alerts"])
        cap = max(50, min(10000, cap))
        _app_config["max_alerts"] = cap
        changed["max_alerts"] = cap
        
    _save_config()
    
    return {"status": "updated", "config": _app_config, "changed": changed}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

