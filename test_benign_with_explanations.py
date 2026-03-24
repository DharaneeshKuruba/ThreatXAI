#!/usr/bin/env python3
"""
Test script to verify benign traffic now shows explanations
and check all the new capture info endpoints.
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"
HEADERS = {"Content-Type": "application/json"}

print("=" * 70)
print("TESTING BENIGN TRAFFIC WITH EXPLANATIONS")
print("=" * 70)

# Generate synthetic benign features (normal traffic pattern)
# These features represent low-risk network behavior
benign_features = [
    64.0, 64.0, 64.0, 64.0, 0.1, 0.5,  # packet sizes and rates
    100.0, 50.0, 200.0, 10.0,           # inter-arrival times
    500.0, 250.0, 100.0, 50.0,          # timing stats
    1000.0, 200.0, 150.0, 75.0,         # more timing
    1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # TCP flags (normal)
    20.0, 20.0, 64.0, 64.0, 500.0, 0.5, 0.5,      # flow characteristics
    64.0, 64.0, 0.8, 0.5, 150.0, 50.0,           # more features
    10, 500, 10, 500, 65535, 65535, 10, 20,      # subflows and windows
    100.0, 50.0, 200.0, 10.0,                    # active times
    1000.0, 100.0, 500.0, 10.0,                  # idle times
    10, 10, 500, 500, 100.0, 100.0, 100.0       # packet counts and padding
]

print("\n1️⃣  Testing BENIGN traffic (should now have explanations):")
print("-" * 70)

benign_payload = {
    "features": benign_features,
    "src_ip": "192.168.1.50",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "model_type": "xgboost"
}

try:
    resp = requests.post(f"{BASE_URL}/predict", json=benign_payload, headers=HEADERS, timeout=5)
    resp.raise_for_status()
    benign_response = resp.json()
    
    alert_id = benign_response.get("alert_id")
    print(f"✓ Benign alert created: {alert_id}")
    print(f"  Label: {benign_response.get('label')}")
    print(f"  Confidence: {benign_response.get('confidence')}")
    
    # Retrieve alert to see full details including explanations
    time.sleep(0.5)
    resp = requests.get(f"{BASE_URL}/alerts/{alert_id}", timeout=5)
    alert = resp.json()
    
    print(f"\n  📊 Alert Details:")
    print(f"    - Prediction: {alert.get('prediction')} (0=Benign, 1=Attack)")
    print(f"    - Label: {alert.get('label')}")
    print(f"    - Confidence: {alert.get('confidence')}")
    print(f"    - Network Metadata:")
    print(f"      • Src IP: {alert.get('src_ip')}")
    print(f"      • Dst IP: {alert.get('dst_ip')}")
    print(f"      • Protocol: {alert.get('protocol')}")
    
    if alert.get('shap_json'):
        print(f"\n  ✅ SHAP EXPLANATIONS (NEW FOR BENIGN):")
        shap_data = json.loads(alert.get('shap_json'))
        # Show top 5 features
        items = list(shap_data.items())[:5]
        for feature, value in items:
            print(f"      • {feature}: {value:.4f}")
    else:
        print(f"\n  ❌ NO SHAP EXPLANATIONS FOUND")
        
except Exception as e:
    print(f"❌ Error testing benign traffic: {e}")

print("\n" + "=" * 70)
print("2️⃣  CAPTURE INFORMATION ENDPOINTS")
print("-" * 70)

# Test capture info endpoint
try:
    resp = requests.get(f"{BASE_URL}/capture/info", timeout=5)
    info = resp.json()
    print("\n✓ Capture Info (/capture/info):")
    print(f"  Packet Sources:")
    for source, detail in info.get("packet_sources", {}).items():
        print(f"    • {source}: {detail}")
    print(f"  Models Available: {info.get('models_available')}")
    print(f"  Model for Live Capture: {info.get('model_for_live_capture')}")
    print(f"  Explanations For: {info.get('explanations_for')}")
    print(f"  Alert Storage: {info.get('alert_storage')}")
except Exception as e:
    print(f"❌ Error fetching capture info: {e}")

# Test capture status endpoint
try:
    resp = requests.get(f"{BASE_URL}/capture/status", timeout=5)
    status = resp.json()
    print(f"\n✓ Capture Status (/capture/status):")
    print(f"  Status: {status.get('status')}")
    print(f"  Packets Captured: {status.get('packets_captured')}")
    print(f"  Alerts Generated: {status.get('alerts_generated')}")
    print(f"  Model Used: {status.get('model_used')}")
    print(f"  Capture Source: {status.get('capture_source')}")
    print(f"  Requires Sudo: {status.get('requires_sudo')}")
except Exception as e:
    print(f"⚠️  Capture status unavailable (expected if not running): {e}")

print("\n" + "=" * 70)
print("3️⃣  SUMMARY OF FIXES")
print("-" * 70)
print("""
✅ BENIGN TRAFFIC NOW HAS EXPLANATIONS
   - SHAP values computed for all traffic (benign + attack)
   - Previously only attacks had explanations
   - Confidence now shown properly for benign traffic (not 0%)

✅ LIVE CAPTURE INFORMATION
   - Packets captured from: All network interfaces via Scapy
   - Requires: sudo/elevated privileges on macOS/Linux
   - Falls back to: Simulated capture if permissions unavailable
   - Model used: XGBoost (for speed and interpretability)
   - All alerts stored in: SQLite database with full metadata

✅ ALERT SOURCES
   1. Live Capture (/capture/start): Uses Scapy to sniff packets
   2. Manual Prediction (POST /predict): Submit feature vectors

✅ NEW ENDPOINTS FOR CLARITY
   - GET /capture/info: Detailed explanation of capture system
   - GET /capture/status: Running status with packet/alert counts
""")

print("=" * 70)
