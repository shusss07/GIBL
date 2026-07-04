import pandas as pd
import os
import sys
import argparse
import joblib

# Add Flow/ dir for flow.py and Correlational/ dir for config.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Correlational"))

from flow import train, score, load_and_clean

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
MODEL_FILES = [
    "if_model.pkl", "if_scaler.pkl", "xgb_model.pkl",
    "normal_ja3_set.pkl", "swift_stats.pkl", "src_stats.pkl",
]

def models_exist():
    """Check if all pre-trained model files are on disk."""
    return all(os.path.exists(os.path.join(MODELS_DIR, f)) for f in MODEL_FILES)

def load_models():
    """Load pre-trained models from disk."""
    print("[2] Loading pre-trained models from disk...")
    if_model = joblib.load(os.path.join(MODELS_DIR, "if_model.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "if_scaler.pkl"))
    xgb_model = joblib.load(os.path.join(MODELS_DIR, "xgb_model.pkl"))
    normal_ja3_set = joblib.load(os.path.join(MODELS_DIR, "normal_ja3_set.pkl"))
    swift_stats = joblib.load(os.path.join(MODELS_DIR, "swift_stats.pkl"))
    src_stats = joblib.load(os.path.join(MODELS_DIR, "src_stats.pkl"))
    print("    All models loaded successfully.")
    return if_model, scaler, xgb_model, normal_ja3_set, swift_stats, src_stats

def main():
    parser = argparse.ArgumentParser(description="GIBL Flow Agent Runner")
    parser.add_argument("--retrain", action="store_true",
                        help="Force retraining even if saved models exist")
    args = parser.parse_args()

    print("=" * 60)
    print("  FLOW AGENT RUNNER")
    print("=" * 60)
    
    print("[1] Loading netflow records...")
    df = load_and_clean("/Users/pratik/Downloads/Track D/netflow_records.csv", 
                        "/Users/pratik/Downloads/Track D/zeek_conn_logs.csv")
    print(f"    Loaded {len(df):,} flows")
    
    # Merge flow labels (needed for training, harmless for scoring)
    labels = pd.read_csv("/Users/pratik/Downloads/Track D/ids_labels_train.csv")
    df = df.merge(labels[["flow_id", "is_attack"]], on="flow_id", how="left")
    df["flow_label"] = df["is_attack"].apply(lambda x: "ATTACK" if x == True else "NORMAL")
    
    print(f"    Attack flows in training: {(df['flow_label'] == 'ATTACK').sum():,}")
    
    if models_exist() and not args.retrain:
        if_model, scaler, xgb_model, normal_ja3_set, swift_stats, src_stats = load_models()
    else:
        print("[2] Training models (this may take a few minutes)...")
        if_model, scaler, xgb_model, normal_ja3_set, swift_stats, src_stats = train(df, model_type="both")
    
    print("[3] Scoring all flows...")
    df_scored = score(df, if_model, scaler, xgb_model,
                      normal_ja3_set=normal_ja3_set, swift_stats=swift_stats, src_stats=src_stats)
    
    # Output exactly what correlation_agent needs: 'flow_id' and 'flow_score'
    df_scored = df_scored.rename(columns={"attack_probability": "flow_score"})
    
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "outputs")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "flow_scores.csv")
    print(f"[4] Saving {len(df_scored):,} scores to {out_path}...")
    df_scored[["flow_id", "flow_score"]].to_csv(out_path, index=False)
    print("[DONE] Flow agent completed successfully.")

if __name__ == "__main__":
    main()
