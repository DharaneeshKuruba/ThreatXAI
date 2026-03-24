"""services/explain_service.py — SHAP + LIME wrappers for FastAPI"""

import sys
import os
import numpy as np
import logging

log = logging.getLogger(__name__)

ML_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "ml")
sys.path.insert(0, ML_DIR)


def get_shap_explanation(model, instance: np.ndarray, feature_names: list,
                          model_type: str = "xgboost") -> dict:
    from explain import shap_local_explanation
    return shap_local_explanation(model, instance, feature_names, model_type)


def get_lime_explanation(model, instance: np.ndarray,
                          X_train: np.ndarray, feature_names: list,
                          model_type: str = "xgboost") -> dict:
    from explain import lime_local_explanation
    return lime_local_explanation(model, instance, X_train, feature_names, model_type)


def get_global_shap(model, X: np.ndarray, feature_names: list,
                     model_type: str = "xgboost") -> dict:
    from explain import shap_global_summary
    return shap_global_summary(model, X, feature_names, model_type)
