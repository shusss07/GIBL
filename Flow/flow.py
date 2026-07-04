# cluade.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
import joblib
import os
from config import (KNOWN_C2_JA3_HASH, SWIFT_SQL_PORT,
                    ENCRYPTED_DNS_PORT, C2_BEACON_DAY,
                    C2_BEACON_HOUR_START, C2_BEACON_HOUR_END,
                    SEGMENT_RISK, PORT_RISK)


def load_and_clean(netflow_path, zeek_path=None):
    df = pd.read_csv(netflow_path, low_memory=False)
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    df = df.drop_duplicates(subset=['flow_id'])
    print(f"Netflow loaded: {len(df):,} rows")

    if zeek_path and os.path.exists(zeek_path):
        zeek = pd.read_csv(zeek_path, low_memory=False,
                           usecols=['id_orig_h', 'id_resp_h', 'ja3_hash'])
        zeek = zeek.rename(columns={'id_orig_h': 'src_ip', 'id_resp_h': 'dst_ip'})
        ja3_agg = (zeek.groupby(['src_ip', 'dst_ip'])['ja3_hash']
                   .agg(lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else 'UNKNOWN')
                   .reset_index())
        df = df.merge(ja3_agg, on=['src_ip', 'dst_ip'], how='left')
        df['ja3_hash'] = df['ja3_hash'].fillna('UNKNOWN')
        print("Zeek JA3 joined.")
    else:
        df['ja3_hash'] = 'UNKNOWN'
    return df


def engineer_features(df, normal_ja3_set=None, swift_stats=None, src_stats=None):
    f = pd.DataFrame({'flow_id': df['flow_id']})
    dur = df['duration_sec'].clip(lower=0.001)

    # ── Core traffic features ─────────────────────────────────
    f['bytes_sent_per_sec']   = df['bytes_sent'].fillna(0) / dur
    f['bytes_per_pkt']        = (df['bytes_sent'].fillna(0) /
                                 df['packets_sent'].clip(lower=1))
    f['pkt_sent_ratio']       = (df['packets_sent'].fillna(0) /
                                 (df['packets_sent'].fillna(0) +
                                  df['packets_recv'].fillna(0)).clip(lower=1))
    #f['duration_sec']         = df['duration_sec'].fillna(0)

    # ── Segment features ─────────────────────────────────────
    f['segment_risk']         = df['segment'].map(SEGMENT_RISK).fillna(0.1)
    f['is_internal_to_ext']   = (
        df['is_internal_src'].astype(bool) &
        ~df['is_internal_dst'].fillna(False).astype(bool)
    ).astype(int)
    f['swift_direct_internet'] = (
        (df['segment'] == 'SWIFT') &
        f['is_internal_to_ext']
    ).astype(int)

    # ── Port features ─────────────────────────────────────────
    f['dst_port_risk']        = df['dst_port'].map(PORT_RISK).fillna(0.05)
    f['is_swift_sql']         = (
        (df['segment'] == 'SWIFT') &
        (df['dst_port'] == SWIFT_SQL_PORT)
    ).astype(int)
    f['is_encrypted_dns']     = (
        (df['dst_port'] == ENCRYPTED_DNS_PORT) &
        (df['segment'] == 'WORKSTATION')
    ).astype(int)

    # ── Temporal features ─────────────────────────────────────
    st = df['start_time']
    f['hour_sin']             = np.sin(2 * np.pi * st.dt.hour / 24)
    f['hour_cos']             = np.cos(2 * np.pi * st.dt.hour / 24)
    f['dow_sin']              = np.sin(2 * np.pi * st.dt.dayofweek / 7)
    f['dow_cos']              = np.cos(2 * np.pi * st.dt.dayofweek / 7)
    f['is_c2_time_window']    = (
        (st.dt.dayofweek == C2_BEACON_DAY) &
        (st.dt.hour >= C2_BEACON_HOUR_START) &
        (st.dt.hour < C2_BEACON_HOUR_END)
    ).astype(int)

    # ── JA3 features ─────────────────────────────────────────
    f['is_known_c2_ja3'] = (df['ja3_hash'] == KNOWN_C2_JA3_HASH).astype(int)

    # Use provided normal_ja3_set or compute from labels (training)
    if normal_ja3_set is not None:
        f['ja3_unseen_in_normal'] = (~df['ja3_hash'].isin(normal_ja3_set)).astype(int)
    else:
        if 'flow_label' in df.columns:
            # FIX: correct bracket placement
            normal_ja3_set = set(df[df['flow_label'] == 'NORMAL']['ja3_hash'].unique())
            f['ja3_unseen_in_normal'] = (~df['ja3_hash'].isin(normal_ja3_set)).astype(int)
        else:
            f['ja3_unseen_in_normal'] = 0

    # ── TCP flags ─────────────────────────────────────────────
    f['flag_syn_only'] = (df['tcp_flags'] == 'S').astype(int)

    # ── Per‑source aggregates ────────────────────────────────
    # Add src_ip column to f so we can merge safely
    f['src_ip'] = df['src_ip']

    if src_stats is not None:
        # Use pre‑computed stats from training
        f = f.merge(src_stats, on='src_ip', how='left')
        f['unique_dst_ips'] = f['unique_dst_ips'].fillna(0)
        f['flow_count'] = f['flow_count'].fillna(0)
    else:
        # Compute stats from training data
        src_stats = (df.groupby('src_ip')
                     .agg(unique_dst_ips=('dst_ip', 'nunique'),
                          flow_count=('flow_id', 'count'))
                     .reset_index())
        f = f.merge(src_stats, on='src_ip', how='left')

    # Drop src_ip after merging – it's not a feature for the models
    f = f.drop(columns=['src_ip'])

    # ── Swift SQL rolling 2‑min rate ─────────────────────────
    swift_mask = (df['segment'] == 'SWIFT') & (df['dst_port'] == SWIFT_SQL_PORT)
    if swift_mask.sum() > 0:
        swift_df = df[swift_mask].copy().set_index('start_time').sort_index()
        rolling = (swift_df.groupby('src_ip')['flow_id']
                   .rolling('2min').count())
        swift_df['count_2min'] = rolling.values

        if swift_stats is not None:
            mean = swift_stats['mean']
            std = swift_stats['std']
            swift_df['swift_query_zscore'] = (swift_df['count_2min'] - mean) / std
        else:
            mean = swift_df['count_2min'].mean()
            std = swift_df['count_2min'].std() + 1e-9
            swift_df['swift_query_zscore'] = (swift_df['count_2min'] - mean) / std

        swift_df['swift_rate_exceeded'] = (swift_df['count_2min'] > 400).astype(int)
        swift_df = swift_df.reset_index()
        f = f.merge(swift_df[['flow_id', 'swift_query_zscore', 'swift_rate_exceeded']],
                    on='flow_id', how='left')
    else:
        f['swift_query_zscore'] = 0
        f['swift_rate_exceeded'] = 0

    f['swift_query_zscore'] = f.get('swift_query_zscore', pd.Series(0, index=f.index)).fillna(0)
    f['swift_rate_exceeded'] = f.get('swift_rate_exceeded', pd.Series(0, index=f.index)).fillna(0)

    # ── Final cleanup ─────────────────────────────────────────
    f = f.replace([np.inf, -np.inf], np.nan).fillna(0)
    return f


# Feature lists

IF_FEATURES = [
    'bytes_per_pkt',
    'pkt_sent_ratio',
    'segment_risk',
    'dst_port_risk',
    'is_internal_to_ext',
    'flag_syn_only',
    'hour_sin',
    'hour_cos',
    'is_c2_time_window',
    'unique_dst_ips'
]

XGB_FEATURES = IF_FEATURES + [
    'is_swift_sql',
    'is_encrypted_dns',
    'swift_direct_internet',
    'is_known_c2_ja3',
    'ja3_unseen_in_normal',
    'dow_sin',
    'dow_cos',
    'flow_count',
    'swift_query_zscore',
    'swift_rate_exceeded'
]


def train(df, model_type='both'):
    import xgboost as xgb
    from sklearn.model_selection import train_test_split

    has_labels = 'flow_label' in df.columns
    if not has_labels:
        raise ValueError("Training requires 'flow_label' column.")

    # Compute features on training set
    f = engineer_features(df)

    # Extract training statistics
    normal_ja3_set = set(df[df['flow_label'] == 'NORMAL']['ja3_hash'].unique())

    src_stats = (df.groupby('src_ip')
                 .agg(unique_dst_ips=('dst_ip', 'nunique'),
                      flow_count=('flow_id', 'count'))
                 .reset_index())

    swift_mask = (df['segment'] == 'SWIFT') & (df['dst_port'] == SWIFT_SQL_PORT)
    if swift_mask.sum() > 0:
        swift_df = df[swift_mask].copy().set_index('start_time').sort_index()
        rolling = (swift_df.groupby('src_ip')['flow_id']
                   .rolling('2min').count())
        swift_df['count_2min'] = rolling.values
        swift_stats = {
            'mean': swift_df['count_2min'].mean(),
            'std': swift_df['count_2min'].std() + 1e-9
        }
    else:
        swift_stats = {'mean': 0, 'std': 1e-9}

    # ── Isolation Forest ──────────────────────────────────────
    if_model = None
    scaler = None
    if model_type in ('both', 'if'):
        normal_flow_ids = df[df['flow_label'] == 'NORMAL']['flow_id']
        X_normal = f[f['flow_id'].isin(normal_flow_ids)][IF_FEATURES].values

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_normal)
        if_model = IsolationForest(
            n_estimators=200,
            contamination=0.001,
            random_state=42,
            n_jobs=-1
        )
        if_model.fit(X_scaled)
        print(f"IF trained on {len(X_scaled):,} normal flows")
        os.makedirs('models', exist_ok=True)
        joblib.dump(if_model, 'models/if_model.pkl')
        joblib.dump(scaler, 'models/if_scaler.pkl')

    # ── XGBoost ──────────────────────────────────────────────
    xgb_model = None
    if model_type in ('both', 'xgb'):
        y = (df['flow_label'] != 'NORMAL').astype(int)
        X = f[XGB_FEATURES]
        X_tr, X_val, y_tr, y_val = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )
        n_neg = (y_tr == 0).sum()
        n_pos = (y_tr == 1).sum()
        xgb_model = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=6,
            learning_rate=0.05,
            scale_pos_weight=n_neg / n_pos,
            eval_metric='auc',
            early_stopping_rounds=30,
            random_state=42,
            n_jobs=-1,
            verbosity=0
        )
        xgb_model.fit(X_tr, y_tr,
                      eval_set=[(X_val, y_val)],
                      verbose=100)
        val_auc = roc_auc_score(y_val, xgb_model.predict_proba(X_val)[:, 1])
        print(f"XGBoost validation AUROC: {val_auc:.4f}")
        joblib.dump(xgb_model, 'models/xgb_model.pkl')
        # Save training statistics for later scoring
        joblib.dump(normal_ja3_set, 'models/normal_ja3_set.pkl')
        joblib.dump(swift_stats, 'models/swift_stats.pkl')
        joblib.dump(src_stats, 'models/src_stats.pkl')
        print("[✓] Training stats saved to models/")

    return if_model, scaler, xgb_model, normal_ja3_set, swift_stats, src_stats


def score(df, if_model, scaler, xgb_model=None,
          xgb_weight=0.7, if_weight=0.3,
          normal_ja3_set=None, swift_stats=None, src_stats=None):
    f = engineer_features(df,
                          normal_ja3_set=normal_ja3_set,
                          swift_stats=swift_stats,
                          src_stats=src_stats)

    X_if = scaler.transform(f[IF_FEATURES].values)
    raw = if_model.score_samples(X_if)
    if_scores = np.clip((-0.3 - raw) / 0.5, 0, 1)

    if xgb_model is not None:
        xgb_probs = xgb_model.predict_proba(f[XGB_FEATURES])[:, 1]
        final_prob = xgb_probs * xgb_weight + if_scores * if_weight
    else:
        final_prob = if_scores

    df = df.copy()
    df['attack_probability'] = np.clip(final_prob, 0, 1)
    df['anomaly_score'] = if_scores
    df['severity'] = pd.cut(
        df['attack_probability'],
        bins=[0, 0.6, 0.75, 0.9, 1.0],
        labels=['NORMAL', 'MEDIUM', 'HIGH', 'CRITICAL']
    )
    return df