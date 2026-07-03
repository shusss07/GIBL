"""
Run Behavior Agent - Main Execution Pipeline
=============================================
GIBL AI/ML Hackathon 2026 | Track D | Sentinels of the Network

Usage:
    python run_behavior_agent.py --ueba path/to/ueba.csv --windows path/to/windows.csv --hosts path/to/hosts.csv
    python run_behavior_agent.py   (uses mock data if no arguments provided)

Output:
    behavior_agent_output.csv          -> parent directory (for Correlation Agent)
    behavior_agent_detailed_results.csv -> Behavior_Agent/ folder (for analysis)
"""

import os
import sys
import time
import argparse
import pandas as pd
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Behavior_Agent.behavior_agent import BehaviorAgent


# ==============================================================================
#  Configuration
# ==============================================================================

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(PARENT_DIR, "behavior_agent_output.csv")
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
DETAILED_OUTPUT = os.path.join(AGENT_DIR, "behavior_agent_detailed_results.csv")


# ==============================================================================
#  Data Cleaning Functions (from Data Dictionary S4)
# ==============================================================================

def deduplicate_windows_events(df):
    """
    Deduplicate Windows event logs on (hostname, timestamp, event_id,
    subject_username) within a +-1 second window.
    (Data Dictionary S4: 1.2% duplicate rate)
    """
    original_count = len(df)

    df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values("timestamp_dt")

    # Round timestamps to nearest second for grouping within +-1s
    df["ts_rounded"] = df["timestamp_dt"].dt.round("1s")

    df = df.drop_duplicates(
        subset=["hostname", "ts_rounded", "event_id", "subject_username"],
        keep="first"
    )

    df = df.drop(columns=["ts_rounded"], errors="ignore")
    removed = original_count - len(df)
    print(f"    Deduplication: removed {removed:,} duplicates "
          f"({removed/original_count*100:.1f}%) from {original_count:,} events")
    return df


def impute_missing_ips(df):
    """
    Fill blank source_ip values with 'LOCAL' for local/service logons.
    (Data Dictionary S4: 9% missing rate for type 2 Interactive and type 5 Service)
    """
    mask = df["source_ip"].isna() | (df["source_ip"].astype(str).str.strip() == "")
    n_missing = mask.sum()
    df.loc[mask, "source_ip"] = "LOCAL"
    print(f"    IP imputation: filled {n_missing:,} blank source_ip values with 'LOCAL' "
          f"({n_missing/len(df)*100:.1f}%)")
    return df


# ==============================================================================
#  Data Loading
# ==============================================================================

def load_data(ueba_path=None, windows_path=None, host_path=None):
    """
    Load UEBA events, Windows events, and host profiles.
    Real paths must be provided; mock data generation is removed.
    """
    # Check that mandatory paths are provided and exist
    if not ueba_path:
        print("  [ERROR] --ueba path is required.")
        sys.exit(1)
    if not os.path.exists(ueba_path):
        print(f"  [ERROR] UEBA path does not exist: {ueba_path}")
        sys.exit(1)

    if not host_path:
        print("  [ERROR] --hosts path is required.")
        sys.exit(1)
    if not os.path.exists(host_path):
        print(f"  [ERROR] Host profiles path does not exist: {host_path}")
        sys.exit(1)

    # --- UEBA ---
    print(f"  Loading UEBA data from: {ueba_path}")
    ueba_df = pd.read_csv(ueba_path, low_memory=False)

    # --- Windows ---
    windows_df = None
    if windows_path:
        if os.path.exists(windows_path):
            print(f"  Loading Windows event logs from: {windows_path}")
            windows_df = pd.read_csv(windows_path, low_memory=False)
        else:
            print(f"  [ERROR] Windows path specified but does not exist: {windows_path}")
            sys.exit(1)
    else:
        # Check parent folder for default windows file as convenience
        default_win_path = os.path.join(PARENT_DIR, "windows_event_logs_GIBL.csv")
        if os.path.exists(default_win_path):
            print(f"  Loading Windows event logs from: {default_win_path}")
            windows_df = pd.read_csv(default_win_path, low_memory=False)
        else:
            print("  [WARN] No Windows path provided and default not found -- skipping Windows analysis")

    # --- Host Profiles ---
    print(f"  Loading host profiles from: {host_path}")
    host_df = pd.read_csv(host_path)

    return ueba_df, windows_df, host_df


# ==============================================================================
#  Evaluation Metrics (from Data Dictionary S8)
# ==============================================================================

def compute_evaluation_metrics(y_true, y_scores, y_pred, latencies=None):
    """
    Compute and print all evaluation metrics from S8.1.
    Only runs if ground truth labels are available.
    """
    from sklearn.metrics import (
        roc_auc_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_curve
    )

    print("\n" + "=" * 65)
    print("  EVALUATION METRICS (Data Dictionary S8.1)")
    print("=" * 65)

    # Classification Report
    print("\n  Classification Report:")
    print("  " + "-" * 55)
    report = classification_report(y_true, y_pred,
                                   target_names=["Normal", "Anomaly"],
                                   output_dict=False)
    for line in report.split("\n"):
        print(f"  {line}")

    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n  Confusion Matrix:")
    print(f"  " + "-" * 55)
    print(f"                    Predicted Normal  Predicted Anomaly")
    print(f"  Actual Normal     {cm[0][0]:<18,} {cm[0][1]:,}")
    print(f"  Actual Anomaly    {cm[1][0]:<18,} {cm[1][1]:,}")

    # Key Metrics
    print(f"\n  Key Metrics:")
    print(f"  " + "-" * 55)

    # AUROC
    if len(set(y_true)) > 1:
        auroc = roc_auc_score(y_true, y_scores)
        target_met = "PASS" if auroc > 0.93 else "NEEDS IMPROVEMENT"
        print(f"  AUROC              : {auroc:.4f}  (Target: > 0.93) [{target_met}]")

    # Precision @ 5% FPR
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    idx_5pct = np.where(fpr <= 0.05)[0]
    if len(idx_5pct) > 0:
        best_idx = idx_5pct[-1]
        threshold_at_5pct = thresholds[best_idx]
        y_pred_5pct = (y_scores >= threshold_at_5pct).astype(int)
        prec_5pct = precision_score(y_true, y_pred_5pct, zero_division=0)
        print(f"  Precision @ 5% FPR : {prec_5pct:.4f}  (Target: > 0.75)")

    # Recall
    recall = recall_score(y_true, y_pred, zero_division=0)
    target_met = "PASS" if recall > 0.88 else "NEEDS IMPROVEMENT"
    print(f"  Recall (attack)    : {recall:.4f}  (Target: > 0.88) [{target_met}]")

    # F1
    f1 = f1_score(y_true, y_pred, zero_division=0)
    target_met = "PASS" if f1 > 0.80 else "NEEDS IMPROVEMENT"
    print(f"  F1 Score (attack)  : {f1:.4f}  (Target: > 0.80) [{target_met}]")

    # Latency
    if latencies:
        p95 = np.percentile(latencies, 95) * 1000  # convert to ms
        target_met = "PASS" if p95 < 1000 else "NEEDS IMPROVEMENT"
        print(f"  Latency P95        : {p95:.1f} ms  (Target: < 1000 ms) [{target_met}]")
        print(f"  Latency Mean       : {np.mean(latencies)*1000:.1f} ms")


# ==============================================================================
#  Main Pipeline
# ==============================================================================

def run_behavior_agent(ueba_path=None, windows_path=None, host_path=None):
    """
    Run the complete Behavior Agent pipeline:
      1. Load data (UEBA + Windows + Hosts)
      2. Clean data (dedup + impute)
      3. Train Isolation Forest on UEBA
      4. Score UEBA events (ML + Rules)
      5. Check SWIFT query velocity (Hidden Pattern #2)
      6. Analyze Windows events (12 Event IDs)
      7. Fuse all scores and aggregate by IP
      8. Save outputs
      9. Print evaluation metrics
    """
    start_time = time.time()

    print("=" * 65)
    print("  GIBL BEHAVIOR AGENT v2.0")
    print("  Multi-Source: Isolation Forest + Banking Rules + Windows Forensics")
    print("=" * 65)

    # -- Step 1: Load data --
    print("\n[1/9] Loading data...")
    ueba_df, windows_df, host_df = load_data(ueba_path, windows_path, host_path)
    print(f"    UEBA events    : {len(ueba_df):,}")
    if windows_df is not None:
        print(f"    Windows events : {len(windows_df):,}")
    else:
        print(f"    Windows events : NONE (skipping Windows analysis)")
    print(f"    Host profiles  : {len(host_df):,}")

    # -- Step 2: Clean data --
    print("\n[2/9] Cleaning data...")
    if windows_df is not None:
        windows_df = deduplicate_windows_events(windows_df)
        windows_df = impute_missing_ips(windows_df)
    else:
        print("    No Windows data to clean.")

    # -- Step 3: Initialize and load context --
    print("\n[3/9] Initializing Behavior Agent...")
    agent = BehaviorAgent(
        contamination=0.02,
        n_estimators=200,
        random_state=42,
    )
    agent.load_host_context(host_df)

    # -- Step 4: Train the model --
    print("\n[4/9] Training Isolation Forest model...")
    train_start = time.time()
    agent.fit(ueba_df)
    train_time = time.time() - train_start
    print(f"    Training time: {train_time:.2f} seconds")

    # -- Step 5: Score UEBA events --
    print("\n[5/9] Scoring UEBA events (hybrid: ML + Rules)...")
    score_start = time.time()
    latencies = []
    ueba_results = []
    features = agent._prepare_features(ueba_df)
    ml_scores = agent._ml_score_batch(features)
    for i, idx in enumerate(ueba_df.index):
        t0 = time.time()
        event = ueba_df.loc[idx].to_dict()
        features_row = features.loc[idx]
        result = agent.score_event(event, features_row, ml_score=ml_scores[i])
        latencies.append(time.time() - t0)
        ueba_results.append(result)

        # Update user profile
        username = str(event.get("username", "unknown")).lower()
        profile = agent.user_profiles[username]
        profile["bytes_history"].append(int(event.get("bytes_transferred", 0)))
        profile["peer_scores"].append(float(event.get("peer_group_deviation_score", 0)))
        profile["event_count"] += 1

    score_time = time.time() - score_start
    ueba_scores = [r["score"] for r in ueba_results]
    n_flagged = sum(1 for s in ueba_scores if s >= 0.70)
    print(f"    [BehaviorAgent] UEBA scoring complete:")
    print(f"      Mean score  : {np.mean(ueba_scores):.4f}")
    print(f"      Max score   : {np.max(ueba_scores):.4f}")
    print(f"      Flagged     : {n_flagged:,} events (score >= 0.70)")
    print(f"    Scoring time : {score_time:.2f} seconds")
    print(f"    Throughput   : {len(ueba_results) / max(score_time, 0.01):.0f} events/sec")

    # -- Step 6: SWIFT query velocity (Hidden Pattern #2) --
    print("\n[6/9] Checking SWIFT query velocity (Hidden Pattern #2)...")
    velocity_results = agent.check_swift_query_velocity(ueba_df)

    # -- Step 7: Analyze Windows events --
    print("\n[7/9] Analyzing Windows Security Events...")
    windows_results = []
    if windows_df is not None:
        win_start = time.time()
        windows_results = agent.analyze_windows_events(windows_df)
        win_time = time.time() - win_start
        print(f"    Windows analysis time: {win_time:.2f} seconds")
    else:
        print("    Skipped (no Windows data loaded).")

    # -- Step 8: Save detailed results --
    print(f"\n[8/9] Saving results...")

    # Save detailed per-event results (UEBA + Windows combined)
    all_detailed = []
    for r in ueba_results:
        all_detailed.append({
            "entity": r["entity"],
            "source": r.get("source", "ueba"),
            "timestamp": r["timestamp"],
            "score": r["score"],
            "ml_score": r["ml_score"],
            "rule_score": r["rule_score"],
            "flags": "|".join(r["flags"]) if r["flags"] else "",
            "mitre": "|".join([f"{t[0]}:{t[1]}" for t in r["mitre"]]) if r["mitre"] else "",
            "source_ip": r["source_ip"],
            "username": r["username"],
            "hostname": r["hostname"],
        })
    for r in windows_results:
        all_detailed.append({
            "entity": r["entity"],
            "source": r.get("source", "windows"),
            "timestamp": r["timestamp"],
            "score": r["score"],
            "ml_score": r["ml_score"],
            "rule_score": r["rule_score"],
            "flags": "|".join(r["flags"]) if r["flags"] else "",
            "mitre": "|".join([f"{t[0]}:{t[1]}" for t in r["mitre"]]) if r["mitre"] else "",
            "source_ip": r["source_ip"],
            "username": r["username"],
            "hostname": r["hostname"],
            "event_log_id": r.get("event_log_id", ""),
        })
    for r in velocity_results:
        all_detailed.append({
            "entity": r["entity"],
            "source": r.get("source", "ueba_velocity"),
            "timestamp": r["timestamp"],
            "score": r["score"],
            "ml_score": r["ml_score"],
            "rule_score": r["rule_score"],
            "flags": "|".join(r["flags"]) if r["flags"] else "",
            "mitre": "|".join([f"{t[0]}:{t[1]}" for t in r["mitre"]]) if r["mitre"] else "",
            "source_ip": r["source_ip"],
            "username": r["username"],
            "hostname": r["hostname"],
        })

    detailed_df = pd.DataFrame(all_detailed)
    detailed_df.to_csv(DETAILED_OUTPUT, index=False)
    print(f"    -> {len(detailed_df):,} detailed results saved to {DETAILED_OUTPUT}")

    # Aggregate by source IP
    output_df = agent.aggregate_by_ip(ueba_results, windows_results, velocity_results)
    output_df.to_csv(OUTPUT_FILE, index=False)
    print(f"    -> {len(output_df):,} rows written to {OUTPUT_FILE}")

    # -- Step 9: Summary and Evaluation --
    total_time = time.time() - start_time
    print("\n" + "=" * 65)
    print("  BEHAVIOR AGENT COMPLETE")
    print("=" * 65)
    print(f"  Total time         : {total_time:.2f} seconds")
    print(f"  UEBA events scored : {len(ueba_results):,}")
    print(f"  Windows threats    : {len(windows_results):,}")
    print(f"  SWIFT velocity     : {len(velocity_results):,}")
    print(f"  Unique source IPs  : {len(output_df):,}")

    if not output_df.empty:
        n_anomalous = (output_df["is_behavior_anomaly"] == 1).sum()
        n_normal = len(output_df) - n_anomalous
        print(f"  Normal IPs         : {n_normal:,}")
        print(f"  Anomalous IPs      : {n_anomalous:,}")
        print(f"  Anomaly rate       : {n_anomalous / len(output_df):.1%}")

        # Show top 10 most anomalous IPs
        print(f"\n  Top 10 Most Anomalous IPs:")
        print(f"  {'Source IP':<20} {'Score':<8} {'Flags'}")
        print(f"  {'-' * 60}")
        top10 = output_df.head(10)
        for _, row in top10.iterrows():
            active_flags = []
            for col in output_df.columns:
                if col.startswith("ind_") and row.get(col, 0) == 1:
                    active_flags.append(col.replace("ind_", ""))
            print(f"  {row['source_ip']:<20} {row['behavior_score']:<8.4f} "
                  f"{', '.join(active_flags) if active_flags else 'ml_anomaly'}")

    print(f"\n  Output files:")
    print(f"    -> {OUTPUT_FILE}")
    print(f"    -> {DETAILED_OUTPUT}")
    print("=" * 65)

    # -- Evaluation Metrics (if ground truth is available) --
    has_ueba_labels = "is_anomaly" in ueba_df.columns
    has_windows_labels = (windows_df is not None and "is_anomaly" in windows_df.columns)

    if has_ueba_labels:
        print("\n  [Evaluation] Ground truth labels found in UEBA data.")
        y_true_ueba = ueba_df["is_anomaly"].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int).values
        y_scores_ueba = np.array([r["score"] for r in ueba_results])
        y_pred_ueba = (y_scores_ueba >= 0.70).astype(int)

        compute_evaluation_metrics(y_true_ueba, y_scores_ueba, y_pred_ueba, latencies)

    if has_windows_labels:
        print("\n  [Evaluation] Ground truth labels found in Windows data.")
        y_true_win = windows_df["is_anomaly"].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int).values
        
        # Build lookup from event_log_id -> score
        win_score_map = {r["event_log_id"]: r["score"] for r in windows_results if "event_log_id" in r}
        
        # Build the continuous score vector for all events in windows_df
        y_scores_win = np.array([win_score_map.get(eid, 0.0) for eid in windows_df["event_log_id"]])
        y_pred_win = (y_scores_win >= 0.70).astype(int)
        
        # Run standard evaluation on Windows events
        compute_evaluation_metrics(y_true_win, y_scores_win, y_pred_win)

    return output_df, detailed_df, ueba_results, windows_results


# ==============================================================================
#  CLI Entry Point
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="GIBL Behavior Agent v2.0 - Multi-Source Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_behavior_agent.py                                          # Mock data
  python run_behavior_agent.py --ueba ueba.csv                         # UEBA only
  python run_behavior_agent.py --ueba ueba.csv --windows windows.csv   # Full mode
  python run_behavior_agent.py --ueba ueba.csv --windows win.csv --hosts hosts.csv
        """,
    )
    parser.add_argument(
        "--ueba", type=str, default=None,
        help="Path to ueba_user_behavior.csv"
    )
    parser.add_argument(
        "--windows", type=str, default=None,
        help="Path to windows_event_logs.csv (optional but recommended)"
    )
    parser.add_argument(
        "--hosts", type=str, default=None,
        help="Path to host_profiles.csv"
    )

    args = parser.parse_args()
    run_behavior_agent(ueba_path=args.ueba, windows_path=args.windows, host_path=args.hosts)
