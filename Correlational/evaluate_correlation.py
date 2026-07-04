# evaluate_correlation.py
import pandas as pd
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve, confusion_matrix, precision_score, recall_score, f1_score
import os

def evaluate_correlation():
    print("=" * 60)
    print("  EVALUATING CORRELATION AGENT")
    print("=" * 60)

    # 1. Load correlation scores
    corr_path = "output/correlation_scores.csv"
    if not os.path.exists(corr_path):
        print(f"ERROR: {corr_path} not found. Run correlation_agent.py first.")
        return
    df_scores = pd.read_csv(corr_path)
    print(f"Loaded {len(df_scores):,} correlation scores.")

    # 2. Load labels (use the evaluation labels for hidden test set)
    labels_path = "ids_labels_eval_HIDDEN.csv"
    if not os.path.exists(labels_path):
        print("WARNING: ids_labels_eval_HIDDEN.csv not found. Using training labels for validation.")
        labels_path = "ids_labels_train.csv"
    labels = pd.read_csv(labels_path)
    print(f"Loaded {len(labels):,} labels.")

    # 3. Merge on flow_id
    df = df_scores.merge(labels, on='flow_id', how='inner')
    print(f"Merged: {len(df):,} rows with labels.")

    if df.empty:
        print("No matches found. Check flow_id alignment.")
        return

    # 4. Ground truth and scores
    y_true = df['is_attack'].astype(int)  # True/False -> 1/0
    y_score = df['attack_probability']

    # 5. AUROC
    auroc = roc_auc_score(y_true, y_score)
    print(f"\nAUROC: {auroc:.4f}")

    # 6. Metrics at 5% FPR threshold
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    idx_5pct = np.argmin(np.abs(fpr - 0.05))
    thresh_5pct = thresholds[idx_5pct]
    y_pred_5pct = (y_score >= thresh_5pct).astype(int)

    precision_5 = precision_score(y_true, y_pred_5pct, zero_division=0)
    recall_5 = recall_score(y_true, y_pred_5pct, zero_division=0)
    f1_5 = f1_score(y_true, y_pred_5pct, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_5pct).ravel()

    print(f"\n--- At threshold giving 5% FPR (threshold = {thresh_5pct:.4f}) ---")
    print(f"Precision: {precision_5:.4f}")
    print(f"Recall:    {recall_5:.4f}")
    print(f"F1:        {f1_5:.4f}")
    print(f"Confusion Matrix:")
    print(f"  True Positives:  {tp:,}")
    print(f"  False Positives: {fp:,}")
    print(f"  False Negatives: {fn:,}")
    print(f"  True Negatives:  {tn:,}")

    # 7. Metrics at threshold 0.5
    y_pred_05 = (y_score >= 0.5).astype(int)
    precision_05 = precision_score(y_true, y_pred_05, zero_division=0)
    recall_05 = recall_score(y_true, y_pred_05, zero_division=0)
    f1_05 = f1_score(y_true, y_pred_05, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_05).ravel()

    print(f"\n--- At threshold 0.5 ---")
    print(f"Precision: {precision_05:.4f}")
    print(f"Recall:    {recall_05:.4f}")
    print(f"F1:        {f1_05:.4f}")
    print(f"Confusion Matrix:")
    print(f"  True Positives:  {tp:,}")
    print(f"  False Positives: {fp:,}")
    print(f"  False Negatives: {fn:,}")
    print(f"  True Negatives:  {tn:,}")

    # 8. Class distribution
    attack_rate = y_true.mean()
    print(f"\nAttack rate in evaluation set: {attack_rate:.2%}")

    print("\n" + "=" * 60)
    print("Evaluation complete.")

if __name__ == "__main__":
    evaluate_correlation()