#!/usr/bin/env python3
"""
GIBL IDS — CSV Evaluation Utility
===================================
Reads a raw Netflow CSV file, applies the pre-trained Machine Learning models
and the Cyber Threat Intelligence (CTI) rules, and outputs a "graded" CSV file 
with threat probabilities and severity classifications.

Usage:
  python3 grade_csv.py <input.csv> [output.csv]
"""

import sys
import os
import joblib
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

# Add Flow & Correlational dirs to path
base = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(base, "..", "Flow"))
sys.path.insert(0, os.path.join(base, "..", "Correlational"))

from flow import load_and_clean, score
from config import KNOWN_C2_JA3_HASH, SWIFT_SQL_PORT, ENCRYPTED_DNS_PORT

MODELS_DIR = os.path.join(base, "..", "Flow", "models")

def apply_cti_rules(df):
    """Overrides ML probabilities with deterministic CTI Rules for known signatures."""
    print("[IDS] Applying Cyber Threat Intelligence (CTI) overrides...")
    
    # Defaults
    df['attack_type'] = "Anomalous Traffic (ML)"
    
    # 1. C2 Beacon
    c2_mask = df['ja3_hash'] == KNOWN_C2_JA3_HASH
    df.loc[c2_mask, 'severity'] = 'CRITICAL'
    df.loc[c2_mask, 'attack_probability'] = 1.0
    df.loc[c2_mask, 'attack_type'] = "C2 Beacon (Malicious JA3)"
    
    # 2. SWIFT SQL Probe
    swift_mask = (df['segment'] == 'SWIFT') & (df['dst_port'] == SWIFT_SQL_PORT)
    df.loc[swift_mask, 'severity'] = 'CRITICAL'
    df.loc[swift_mask, 'attack_probability'] = 1.0
    df.loc[swift_mask, 'attack_type'] = "SWIFT SQL Injection Probe"
    
    # 3. Data Exfiltration
    # (High packets, tiny bytes per packet)
    bpp = df['bytes_sent'].fillna(0) / df['packets_sent'].clip(lower=1)
    is_ext = df['is_internal_src'].astype(str) != 'True'
    exfil_mask = is_ext & (bpp < 500)
    df.loc[exfil_mask, 'severity'] = 'CRITICAL'
    df.loc[exfil_mask, 'attack_probability'] = 1.0
    df.loc[exfil_mask, 'attack_type'] = "Data Exfiltration (Small Packets)"
    
    return df

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 grade_csv.py <input_netflow.csv> [output_scored.csv]")
        sys.exit(1)
        
    input_csv = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else input_csv.replace(".csv", "_graded.csv")
    
    if not os.path.exists(input_csv):
        print(f"Error: File '{input_csv}' not found.")
        sys.exit(1)

    print(f"[IDS] Loading models from {MODELS_DIR}...")
    xgb_model      = joblib.load(os.path.join(MODELS_DIR, "xgb_model.pkl"))
    if_model       = joblib.load(os.path.join(MODELS_DIR, "if_model.pkl"))
    if_scaler      = joblib.load(os.path.join(MODELS_DIR, "if_scaler.pkl"))
    normal_ja3_set = joblib.load(os.path.join(MODELS_DIR, "normal_ja3_set.pkl"))
    swift_stats    = joblib.load(os.path.join(MODELS_DIR, "swift_stats.pkl"))
    src_stats      = joblib.load(os.path.join(MODELS_DIR, "src_stats.pkl"))

    print(f"[IDS] Loading and cleaning {input_csv}...")
    df = load_and_clean(input_csv)

    print("[IDS] Engineering features and scoring via ML Models...")
    scored_df = score(
        df, 
        if_model=if_model, 
        scaler=if_scaler, 
        xgb_model=xgb_model,
        normal_ja3_set=normal_ja3_set, 
        swift_stats=swift_stats, 
        src_stats=src_stats
    )

    scored_df = apply_cti_rules(scored_df)
    
    # Clean up output columns for readability
    cols_to_save = ['flow_id', 'src_ip', 'dst_ip', 'segment', 'dst_port', 
                    'attack_probability', 'severity', 'attack_type']
    
    print(f"\n[IDS] Analysis Complete.")
    print(f"      Total flows processed: {len(scored_df):,}")
    
    threats_count = len(scored_df[scored_df['severity'] != 'NORMAL'])
    print(f"      Threats detected:      {threats_count:,}")
    print(f"      Normal flows:          {len(scored_df) - threats_count:,}")
    
    scored_df[cols_to_save].to_csv(output_csv, index=False)
    print(f"[IDS] Saved graded data to: {output_csv}")

if __name__ == "__main__":
    main()
