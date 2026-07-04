# accuracy.py
import pandas as pd
import numpy as np
import warnings
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, roc_curve, confusion_matrix
import os

warnings.filterwarnings('ignore')

from flow import train, score, XGB_FEATURES, IF_FEATURES, engineer_features

def check_local_accuracy(netflow_csv, labels_csv):
    print("=" * 60)
    print("GIBL TRACK D — FINAL NATIVE ACCURACY CHECK")
    print("=" * 60)

    # 1. Load Data
    print("[+] Loading datasets...")
    df = pd.read_csv(netflow_csv, low_memory=False)
    labels = pd.read_csv(labels_csv)

    # Clean and convert datetime
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df = df.dropna(subset=['start_time'])
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    df = df.drop_duplicates(subset=['flow_id'])
    
    # Merge labels
    df = df.merge(labels, on='flow_id', how='inner')
    print(f"    Loaded {len(df):,} strictly labeled rows.")

    # Ensure ja3_hash exists (default)
    if 'ja3_hash' not in df.columns:
        df['ja3_hash'] = 'UNKNOWN'

    y = (df['flow_label'] != 'NORMAL').astype(int)

    # 2. Train/Validation Split (80/20)
    df_train, df_val, y_train, y_val = train_test_split(
        df, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. Train Models (returns training statistics)
    print("\n[+] Training models natively via cluade.train()...")
    if_model, scaler, xgb_model, normal_ja3_set, swift_stats, src_stats = train(df_train, model_type='both')

    # 4. Score Validation Set (using training statistics)
    print("[+] Scoring validation set natively via cluade.score()...")
    scored_val_df = score(df_val, if_model, scaler, xgb_model,
                          xgb_weight=0.7, if_weight=0.3,
                          normal_ja3_set=normal_ja3_set,
                          swift_stats=swift_stats,
                          src_stats=src_stats)

    # 5. Evaluate
    ensemble_auroc = roc_auc_score(y_val, scored_val_df['attack_probability'])

    # Also compute standalone models (using the same feature engineering)
    f_val = engineer_features(df_val,
                              normal_ja3_set=normal_ja3_set,
                              swift_stats=swift_stats,
                              src_stats=src_stats)

    # IF standalone
    X_if_val = scaler.transform(f_val[IF_FEATURES].values)
    raw_if = if_model.score_samples(X_if_val)
    if_probs = np.clip((-0.3 - raw_if) / 0.5, 0, 1)
    if_auroc = roc_auc_score(y_val, if_probs)

    # XGB standalone
    xgb_probs = xgb_model.predict_proba(f_val[XGB_FEATURES])[:, 1]
    xgb_auroc = roc_auc_score(y_val, xgb_probs)

    print("\n" + "="*45)
    print(f"{'MODEL IDENTITY':<25} {'VALIDATION AUROC':<20}")
    print("-"*45)
    print(f"{'Isolation Forest (IF)':<25} {if_auroc:.4f}")
    print(f"{'XGBoost (XGB)':<25} {xgb_auroc:.4f}")
    print(f"{'Ensemble Blend (0.7/0.3)':<25} {ensemble_auroc:.4f}")
    print("="*45)

    # ─── PRIMARY INTRUSION DETECTION METRICS ──────────────────
    print("\n" + "="*60)
    print("PRIMARY INTRUSION DETECTION METRICS (Ensemble)")
    print("="*60)

    # Compute ROC curve to find threshold for 5% FPR
    fpr, tpr, thresholds = roc_curve(y_val, scored_val_df['attack_probability'])
    # Find index where fpr <= 0.05 (closest)
    idx = np.argmin(np.abs(fpr - 0.05))
    thresh_5pct = thresholds[idx]
    # Apply threshold
    y_pred_5pct = (scored_val_df['attack_probability'] >= thresh_5pct).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, y_pred_5pct).ravel()
    precision_5pct = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall_5pct = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_5pct = (2 * precision_5pct * recall_5pct / (precision_5pct + recall_5pct)
               if (precision_5pct + recall_5pct) > 0 else 0)

    # Also compute at threshold 0.5
    y_pred_05 = (scored_val_df['attack_probability'] >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, y_pred_05).ravel()
    precision_05 = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall_05 = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_05 = (2 * precision_05 * recall_05 / (precision_05 + recall_05)
             if (precision_05 + recall_05) > 0 else 0)

    print(f"AUROC: {ensemble_auroc:.4f} (target >0.93)")
    print(f"Precision @ 5% FPR: {precision_5pct:.4f} (target >0.75)")
    print(f"Recall (attack class) @ 5% FPR threshold: {recall_5pct:.4f} (target >0.88)")
    print(f"F1 Score @ 5% FPR threshold: {f1_5pct:.4f} (target >0.80)")
    print(f"--- At threshold 0.5 ---")
    print(f"Precision: {precision_05:.4f}")
    print(f"Recall: {recall_05:.4f}")
    print(f"F1: {f1_05:.4f}")
    print("="*60)

    # ─── DIAGNOSTIC: Per‑feature AUROC ──────────────────────
    print("\n[!] DIAGNOSTIC: Per-feature AUROC on validation set")
    print("-" * 50)

    # Align indices (f_val and y_val should have same rows, but reset to be safe)
    f_val_reset = f_val.reset_index(drop=True)
    y_val_reset = y_val.reset_index(drop=True)

    feature_aurocs = {}
    for col in f_val_reset.columns:
        if col == 'flow_id':
            continue
        if pd.api.types.is_numeric_dtype(f_val_reset[col]):
            try:
                auc = roc_auc_score(y_val_reset, f_val_reset[col])
                feature_aurocs[col] = auc
            except:
                pass

    sorted_feats = sorted(feature_aurocs.items(), key=lambda x: x[1], reverse=True)
    for feat, auc in sorted_feats[:10]:
        print(f"{feat:<30} {auc:.4f}")
    print("-" * 50)

    # ─── Class‑wise means ──────────────────────────────────────
    print("\n[!] Class-wise feature means (top suspicious):")
    for feat, auc in sorted_feats[:5]:
        mean_attack = f_val_reset[y_val_reset == 1][feat].mean()
        mean_normal = f_val_reset[y_val_reset == 0][feat].mean()
        print(f"{feat}: attack mean = {mean_attack:.4f}, normal mean = {mean_normal:.4f}")

    # ─── Disjoint values (perfect separators) ─────────────────
    print("\n[!] Features with disjoint values between classes:")
    for col in f_val_reset.columns:
        if col == 'flow_id':
            continue
        if not pd.api.types.is_numeric_dtype(f_val_reset[col]):
            continue
        attack_vals = set(f_val_reset[y_val_reset == 1][col])
        normal_vals = set(f_val_reset[y_val_reset == 0][col])
        if not attack_vals.intersection(normal_vals):
            print(f"   ⚠️  '{col}' has disjoint values between attack and normal!")
            print(f"      Attack values: {list(attack_vals)[:5]}")
            print(f"      Normal values: {list(normal_vals)[:5]}")

if __name__ == "__main__":
    NETFLOW_PATH = r"C:\Users\Lenovo\hackathon\Track D\Track D\netflow_records.csv"
    LABELS_PATH = r"C:\Users\Lenovo\hackathon\Track D\Track D\ids_labels_train.csv"
    if os.path.exists(NETFLOW_PATH) and os.path.exists(LABELS_PATH):
        check_local_accuracy(NETFLOW_PATH, LABELS_PATH)
    else:
        print("Error: Verify data directory file paths explicitly.")