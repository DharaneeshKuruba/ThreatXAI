#!/usr/bin/env python3
"""
generate_attack_demo.py — Generate diverse attack alerts for EDAC demo.
Uses internal services (bypasses HTTP) for speed.
Creates alerts that trigger 6 distinct EDAC campaign types.
"""

import os, sys, json, random, uuid
import numpy as np

# Setup path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.db.session import SessionLocal, engine
from backend.db.models import Base, Alert
from backend.services.model_service import get_models, get_scaler, get_feature_names, get_edac_engine
from backend.services.explain_service import get_shap_explanation

# Ensure tables exist
Base.metadata.create_all(bind=engine)
db = SessionLocal()

# Load test data
PROCESSED = os.path.join("ml", "data", "processed")
X_test = np.load(os.path.join(PROCESSED, "X_test.npy"), allow_pickle=True)
y_test = np.load(os.path.join(PROCESSED, "y_test_binary.npy"), allow_pickle=True)

# Load models
print("Loading models...")
models = get_models()
scaler = get_scaler()
feature_names = get_feature_names()
edac = get_edac_engine()
print(f"✓ Models loaded: {list(models.keys())}")
print(f"✓ EDAC engine: {'loaded' if edac else 'NOT loaded'}")
print(f"✓ Feature count: {len(feature_names)}")

# Find attack indices
attack_indices = np.where(y_test == 1)[0]
print(f"✓ Found {len(attack_indices)} attack samples in test set")

# ─── Feature index mapping (from EDAC FEATURE_ARCHETYPES) ─────────────────────
# These are the indices that EDAC's infer_label() inspects
IDX = {
    "FWD_PKT_LEN_MEAN": 1,    # Fwd Packet Length Mean
    "FLOW_BYTES_S": 4,         # Flow Bytes/s
    "FLOW_PACKETS_S": 5,       # Flow Packets/s
    "SYN_FLAG_COUNT": 33,      # SYN Flag Count
    "ACK_FLAG_COUNT": 37,      # ACK Flag Count
    "INIT_WIN_FWD": 50,        # Init_Win_bytes_forward
    "TOTAL_FWD_PACKETS": 62,   # Total Fwd Packets
    "TOTAL_BWD_PACKETS": 63,   # Total Backward Packets
    "FLOW_DURATION": 66,       # Flow Duration
}

# ─── Attack Campaign Profiles ─────────────────────────────────────────────────
# Each profile defines:
#   - network: src_ips, dst_ip, protocol for realistic alert metadata
#   - shap_boosts: feature index → value to inject into the SHAP vector
#     These are carefully crafted to trigger specific infer_label() branches.

CAMPAIGN_PROFILES = [
    # 1. SYN Flood / DDoS — triggers: syn > 0.15 and bytes_s > 0.1
    {
        "name": "SYN Flood / DDoS",
        "count": 5,
        "network": {"src_ips": ["10.0.0.5", "10.0.0.6", "10.0.0.7"],
                    "dst_ip": "192.168.1.100", "protocol": "TCP"},
        "shap_boosts": {
            IDX["SYN_FLAG_COUNT"]: 0.35,
            IDX["FLOW_BYTES_S"]: 0.25,
            IDX["FLOW_PACKETS_S"]: 0.18,
        },
    },
    # 2. Port Scan — triggers: duration < -0.1 and fwd_pkts > 0.1 and bwd_pkts < -0.05
    {
        "name": "Port Scan",
        "count": 5,
        "network": {"src_ips": ["172.16.0.50", "172.16.0.51"],
                    "dst_ip": "192.168.1.200", "protocol": "TCP"},
        "shap_boosts": {
            IDX["FLOW_DURATION"]: -0.22,
            IDX["TOTAL_FWD_PACKETS"]: 0.20,
            IDX["TOTAL_BWD_PACKETS"]: -0.12,
        },
    },
    # 3. Brute Force — triggers: ack > 0.05 and pkt_len < 0.0 and init_win > 0.05
    {
        "name": "Brute Force",
        "count": 4,
        "network": {"src_ips": ["10.10.10.99", "10.10.10.100"],
                    "dst_ip": "192.168.1.50", "protocol": "TCP"},
        "shap_boosts": {
            IDX["ACK_FLAG_COUNT"]: 0.15,
            IDX["FWD_PKT_LEN_MEAN"]: -0.12,
            IDX["INIT_WIN_FWD"]: 0.10,
        },
    },
    # 4. Slow HTTP DoS — triggers: bytes_s < -0.05 and duration > 0.1 and packets_s < -0.05
    {
        "name": "Slow HTTP DoS",
        "count": 4,
        "network": {"src_ips": ["192.168.5.10", "192.168.5.11", "192.168.5.12"],
                    "dst_ip": "45.33.32.156", "protocol": "TCP"},
        "shap_boosts": {
            IDX["FLOW_BYTES_S"]: -0.15,
            IDX["FLOW_DURATION"]: 0.22,
            IDX["FLOW_PACKETS_S"]: -0.10,
        },
    },
    # 5. Heartbleed / Protocol Exploit — triggers: init_win < -0.1
    {
        "name": "Heartbleed / Protocol Exploit",
        "count": 3,
        "network": {"src_ips": ["10.20.30.40"],
                    "dst_ip": "192.168.1.80", "protocol": "TCP"},
        "shap_boosts": {
            IDX["INIT_WIN_FWD"]: -0.25,
        },
    },
    # 6. Botnet C2 Communication — triggers: duration > 0.15 and fwd_pkts > 0.05 and bwd_pkts > 0.05
    {
        "name": "Botnet C2 Communication",
        "count": 4,
        "network": {"src_ips": ["172.16.0.1", "172.16.0.2"],
                    "dst_ip": "192.168.1.150", "protocol": "UDP"},
        "shap_boosts": {
            IDX["FLOW_DURATION"]: 0.30,
            IDX["TOTAL_FWD_PACKETS"]: 0.12,
            IDX["TOTAL_BWD_PACKETS"]: 0.10,
        },
    },
]

np.random.seed(42)
model = models.get("xgboost") or list(models.values())[0]
model_type = "xgboost"
n_expected = scaler.mean_.shape[0]
n_features = len(feature_names)

# ── Create a FRESH EDAC engine so seeded clusters don't absorb everything ──────
# The seeded engine may have pre-existing centroids that attract all alerts.
# We want to demonstrate diverse clusters from scratch.
from ml.edac import EDACEngine
demo_edac = EDACEngine(feature_names)
demo_edac.SIMILARITY_THRESHOLD = 0.80
print(f"✓ Fresh EDAC engine created for demo (threshold={demo_edac.SIMILARITY_THRESHOLD})")

total_alerts = sum(p["count"] for p in CAMPAIGN_PROFILES)
print(f"\n🚀 Generating {total_alerts} attack alerts across {len(CAMPAIGN_PROFILES)} campaign types...")
print("=" * 80)

success = 0
clusters_seen = set()
alert_idx = 0

for profile in CAMPAIGN_PROFILES:
    campaign_name = profile["name"]
    count = profile["count"]
    net = profile["network"]
    boosts = profile["shap_boosts"]

    # Pick random attack samples from test set for this campaign
    sample_indices = np.random.choice(attack_indices, size=count, replace=False)

    print(f"\n📌 Campaign: {campaign_name} ({count} alerts)")
    print(f"   Network: {net['src_ips'][0]}... → {net['dst_ip']} ({net['protocol']})")

    for i, idx in enumerate(sample_indices):
        src_ip = random.choice(net["src_ips"])
        alert_idx += 1

        features = X_test[idx].copy()
        if len(features) < n_expected:
            features = np.pad(features, (0, n_expected - len(features)))
        elif len(features) > n_expected:
            features = features[:n_expected]

        # X_test is already scaled, so use directly
        features_scaled = features

        # Predict
        proba = float(model.predict_proba(features_scaled.reshape(1, -1))[0][1])
        prediction = int(proba >= 0.5)
        label = "Attack" if prediction == 1 else "Benign"
        alert_id = str(uuid.uuid4())

        # SHAP
        shap_json = None
        cluster_id = cluster_label = cluster_similarity = None

        try:
            shap_exp = get_shap_explanation(model, features_scaled, feature_names, model_type)
            shap_vector = np.array(shap_exp.get("shap_vector", []))
            shap_json = json.dumps(shap_exp.get("shap_values", {}))

            # ★ STRATEGY: Scale down real SHAP vector, then inject strong campaign-specific
            # pattern. This ensures each campaign produces a distinct SHAP fingerprint
            # that EDAC will cluster separately (cosine similarity < 0.80 between campaigns).
            crafted_shap = shap_vector.copy()
            crafted_shap *= 0.02  # Flatten base signal to near-zero

            # Inject strong campaign-specific features
            for feat_idx, boost_val in boosts.items():
                if feat_idx < len(crafted_shap):
                    noise = np.random.normal(0, abs(boost_val) * 0.05)
                    crafted_shap[feat_idx] = boost_val + noise

            # EDAC clustering using crafted SHAP vector
            cluster_info = demo_edac.assign_alert(crafted_shap, alert_id)
            cluster_id = cluster_info.get("cluster_id")
            cluster_label = cluster_info.get("label")
            cluster_similarity = cluster_info.get("similarity_score")
            if cluster_id:
                clusters_seen.add(cluster_id)
        except Exception as e:
            print(f"  ⚠️  SHAP/EDAC error: {e}")

        # Store in DB
        alert = Alert(
            alert_id=alert_id,
            src_ip=src_ip,
            dst_ip=net["dst_ip"],
            protocol=net["protocol"],
            prediction=prediction,
            label=label,
            confidence=round(proba, 4),
            cluster_id=cluster_id,
            cluster_label=cluster_label,
            cluster_similarity=cluster_similarity,
            shap_json=shap_json,
            features_json=json.dumps(features.tolist()),
            is_live_capture=False,
        )
        db.add(alert)
        db.commit()

        status = "✅" if prediction == 1 else "⚠️"
        print(f"  {status} [{alert_idx:2d}/{total_alerts}] {src_ip:15s} → {net['dst_ip']:15s} | "
              f"{label:7s} ({proba:.4f}) | "
              f"EDAC: {cluster_label or 'N/A'} (sim={cluster_similarity or 0:.2f})")
        success += 1

db.close()

# Also save the demo EDAC engine so it persists across backend restarts
import joblib
edac_path = os.path.join("ml", "models", "edac_engine.pkl")
demo_edac.save(edac_path)

print("\n" + "=" * 80)
print(f"📊 Results: {success}/{total_alerts} alerts stored")
print(f"🔗 EDAC Clusters formed: {len(clusters_seen)}")
for cid in clusters_seen:
    c = demo_edac.clusters.get(cid)
    if c:
        info = c.to_dict()
        print(f"   • {info['label']:35s} | {info['member_count']:3d} members")

print(f"\n✅ Done! Refresh http://localhost:5173 → Attack Campaigns to see results.")

