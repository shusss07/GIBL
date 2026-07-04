import os
import sys
import pandas as pd
import joblib

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(base, "Flow"))
sys.path.insert(0, os.path.join(base, "Correlational"))
from flow import engineer_features, XGB_FEATURES

MODELS_DIR  = os.path.join(base, "Flow", "models")
xgb_model      = joblib.load(os.path.join(MODELS_DIR, "xgb_model.pkl"))
normal_ja3_set = joblib.load(os.path.join(MODELS_DIR, "normal_ja3_set.pkl"))
swift_stats    = joblib.load(os.path.join(MODELS_DIR, "swift_stats.pkl"))
src_stats      = joblib.load(os.path.join(MODELS_DIR, "src_stats.pkl"))

df = pd.read_csv(os.path.join(base, "demo/live_netflow.log"))

for ip in ["45.142.212.65", "10.30.1.200", "10.10.3.59"]:
    subset = df[df["src_ip"] == ip].head(2)
    for _, row in subset.iterrows():
        row_dict = row.to_dict()
        row_dict['is_internal_src'] = str(row_dict['is_internal_src']) == 'True'
        row_dict['is_internal_dst'] = str(row_dict['is_internal_dst']) == 'True'
        
        row_df = pd.DataFrame([row_dict])
        row_df['start_time'] = pd.to_datetime(row_df['start_time'])
        row_df['tcp_flags'] = 'PA'
        
        f_df = engineer_features(row_df, normal_ja3_set, swift_stats, src_stats)
        for col in XGB_FEATURES:
            if col not in f_df.columns:
                f_df[col] = 0.0
        X = f_df[XGB_FEATURES].fillna(0)
        prob = xgb_model.predict_proba(X)[0][1]
        print(f"IP: {ip}, Port: {row_dict['dst_port']}, Prob: {prob:.4f}")
