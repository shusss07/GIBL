"""
GIBL IDS Live Engine — Real-Time Threat Detection
===================================================
Tails the live netflow log produced by target_server.py,
runs the pre-trained XGBoost model on every flow, and issues
active block commands when a threat is detected.
"""

import os
import sys
import time
import pandas as pd
import urllib.request
import json
import warnings
warnings.filterwarnings('ignore')

# Add Flow and Correlational directories to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Flow"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Correlational"))
from flow import engineer_features, XGB_FEATURES
from config import KNOWN_C2_JA3_HASH, SWIFT_SQL_PORT, ENCRYPTED_DNS_PORT
import numpy as np
import joblib

MODELS_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Flow", "models")
LOG_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_netflow.log")
ALERTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_alerts.log")
BLOCK_URL   = "http://localhost:8080/api/block"
THRESHOLD   = 0.86

if os.path.exists(ALERTS_FILE):
    try:
        os.remove(ALERTS_FILE)
    except Exception:
        pass

blocked_ips = set()
alert_cache = {}
stats = {"total": 0, "benign": 0, "threats": 0}

def load_models():
    print("[IDS] Loading trained XGBoost + Isolation Forest models...")
    xgb_model      = joblib.load(os.path.join(MODELS_DIR, "xgb_model.pkl"))
    normal_ja3_set = joblib.load(os.path.join(MODELS_DIR, "normal_ja3_set.pkl"))
    swift_stats    = joblib.load(os.path.join(MODELS_DIR, "swift_stats.pkl"))
    src_stats      = joblib.load(os.path.join(MODELS_DIR, "src_stats.pkl"))
    print(f"[IDS] Models loaded.  Threshold = {THRESHOLD}")
    return xgb_model, normal_ja3_set, swift_stats, src_stats


def gated_fusion(flow_score, behavior_score, packet_score):
    """Correlation Engine: fuses scores from the 3 independent AI agents."""
    gate = 1 / (1 + np.exp(-(flow_score - behavior_score)))
    fused = gate * flow_score + (1 - gate) * behavior_score
    return np.clip(0.85 * fused + 0.15 * packet_score, 0, 1)

def block_ip(ip):
    if ip in ('127.0.0.1', 'localhost', '::1'):
        return
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    try:
        data = json.dumps({"ip": ip}).encode('utf-8')
        req = urllib.request.Request(BLOCK_URL, data=data,
                                     headers={'Content-Type': 'application/json'},
                                     method='POST')
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:
        print(f"[IDS] ⚠  Error blocking {ip}: {e}")


def classify_attack(row, prob):
    """Determine attack type from flow features for richer output.
    Returns (attack_name, severity). Returns (None, None) if no rule matches.
    """
    ja3       = row.get('ja3_hash', 'UNKNOWN')
    port      = int(row.get('dst_port', 0))
    segment   = row.get('segment', '')
    # is_internal_src is already converted to a boolean in run_ids
    is_ext    = not row.get('is_internal_src', True)
    pkts      = float(row.get('packets_sent', 0))
    bps       = float(row.get('bytes_sent', 0)) / max(pkts, 1)
    
    malicious_ja3s = [KNOWN_C2_JA3_HASH, "e7d1e3f2a4b6c8d1", "a7d1e3f2a4b6c8d2"]

    if ja3 in malicious_ja3s:
        return "C2 Beacon (Malicious JA3)", "CRITICAL"
    if segment == 'SWIFT' and port == SWIFT_SQL_PORT:
        return "SWIFT SQL Injection Probe", "CRITICAL"
    if is_ext and bps < 500:
        return "Data Exfiltration (Small Packets)", "CRITICAL"
        
    # If the Correlation Engine flagged it but no specific rule matched:
    if prob > THRESHOLD:
        if port == ENCRYPTED_DNS_PORT:
            return "Suspicious Encrypted DNS", "HIGH"
        if is_ext:
            return "Anomalous External Access", "HIGH"
        if port in (3389, 445):
            return "Anomalous Lateral Movement", "HIGH"
        return "Unknown Anomaly (Correlation Detection)", "MEDIUM"
        
    return None, None


def run_ids(xgb_model, normal_ja3_set, swift_stats, src_stats):
    print(f"[IDS] Monitoring: {LOG_FILE}")
    print("[IDS] Waiting for traffic...\n")

    while not os.path.exists(LOG_FILE):
        time.sleep(0.5)

    with open(LOG_FILE, "r") as f:
        header = f.readline().strip().split(",")
        f.seek(0, 2)       # jump to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue

            values = line.strip().split(",")
            if len(values) != len(header):
                continue

            row = dict(zip(header, values))

            # ── Type conversion ──────────────────────────────
            try:
                row['duration_sec']    = float(row['duration_sec'])
                row['bytes_sent']      = float(row['bytes_sent'])
                row['packets_sent']    = float(row['packets_sent'])
                row['packets_recv']    = float(row['packets_recv'])
                row['is_internal_src'] = row['is_internal_src'] == 'True'
                row['is_internal_dst'] = row['is_internal_dst'] == 'True'
                row['dst_port']        = int(row['dst_port'])
            except Exception:
                continue

            # ── Build single-row DataFrame ───────────────────
            df = pd.DataFrame([row])
            df['start_time'] = pd.to_datetime(df['start_time'])
            df['tcp_flags']  = 'PA'

            # ── Feature engineering ──────────────────────────
            f_df = engineer_features(df, normal_ja3_set, swift_stats, src_stats)
            for col in XGB_FEATURES:
                if col not in f_df.columns:
                    f_df[col] = 0.0
            X = f_df[XGB_FEATURES].fillna(0)

            # ── Predict Flow Score (XGBoost) ─────────────────
            flow_score = float(xgb_model.predict_proba(X)[0][1])
            stats["total"] += 1
            
            # ── Read Simulated Packet & Behavior Scores ──────
            try:
                packet_score = float(row.get('sim_packet_score', 0.05))
                behavior_score = float(row.get('sim_behavior_score', 0.05))
            except Exception:
                packet_score = 0.05
                behavior_score = 0.05

            # ── Correlation Engine Fusion ────────────────────
            correlation_score = float(gated_fusion(flow_score, behavior_score, packet_score))

            attack_name, severity = classify_attack(row, correlation_score)

            if attack_name is not None:
                stats["threats"] += 1
                ip = row['src_ip']
                already = ip in blocked_ips
                block_ip(ip)

                cache_key = (ip, attack_name)
                current_time = time.time()
                if cache_key not in alert_cache or (current_time - alert_cache[cache_key]) > 10.0:
                    alert_cache[cache_key] = current_time
                    
                    # Write to live alerts log
                    alert_data = {
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
                        "ip": ip,
                        "attack_name": attack_name,
                        "severity": severity,
                        "flow_score": round(flow_score, 2),
                        "behavior_score": round(behavior_score, 2),
                        "packet_score": round(packet_score, 2),
                        "correlation_score": round(correlation_score, 2)
                    }
                    try:
                        with open(ALERTS_FILE, "a") as af:
                            af.write(json.dumps(alert_data) + "\n")
                    except Exception:
                        pass

                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "⚪")
                    print(f"[IDS 🚨] {sev_icon} THREAT DETECTED: IP {ip} -> {attack_name}")
                    print(f"         ├── Flow Agent       : {flow_score:.2f}  (Volume/NetFlow)")
                    print(f"         ├── Behavior Agent   : {behavior_score:.2f}  (Host/UEBA)")
                    print(f"         ├── Packet Agent     : {packet_score:.2f}  (Payload/Zeek)")
                    print(f"         └── Correlation Engine: {correlation_score:.2f}  [{severity}]")
                    if not already:
                        print(f"[IDS 🛡️ ] ✅ FIREWALL RULE ADDED — Actively blocking {ip}...")
                    else:
                        print(f"[IDS 🛡️ ] (IP is already in firewall jail)")
                    print()
            else:
                stats["benign"] += 1


if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        try:
            os.remove(LOG_FILE)
        except Exception:
            pass
    xgb_model, normal_ja3_set, swift_stats, src_stats = load_models()
    try:
        run_ids(xgb_model, normal_ja3_set, swift_stats, src_stats)
    except KeyboardInterrupt:
        print(f"\n[IDS] Session stats — Total: {stats['total']} | "
              f"Benign: {stats['benign']} | Threats: {stats['threats']} | "
              f"Blocked IPs: {len(blocked_ips)}")
        sys.exit(0)
