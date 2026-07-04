import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
import warnings


warnings.filterwarnings("ignore")

WINDOWS_LOG   = "/Users/pratik/Downloads/Track D/windows_event_logs.csv"
ZEEK_LOG      = "/Users/pratik/Downloads/Track D/zeek_conn_logs.csv"
CONTAMINATION = 0.05   # expected fraction of anomalies — tune as needed
RANDOM_STATE  = 42
TOP_N         = 20     # how many top threats to print
OUTPUT_CSV    = "../outputs/threat_results.csv"

print("=" * 60)
print("  GIBL Threat Agent — Isolation Forest")
print("=" * 60)

# ── 1. LOAD DATA ─────────────────────────────────────────────────────────────
print("\n[1] Loading data...")
win = pd.read_csv(WINDOWS_LOG)
zeek = pd.read_csv(ZEEK_LOG)
print(f"    Windows events : {len(win):,} rows")
print(f"    Zeek conn logs : {len(zeek):,} rows")

# ── 2. WINDOWS FEATURES ──────────────────────────────────────────────────────
print("\n[2] Engineering Windows behavioral features...")
 
win["timestamp"] = pd.to_datetime(win["timestamp"])
win["source_ip"] = win["source_ip"].fillna("LOCAL")

# Behavioral event-type flags (continuous counts, not binary labels)
win["is_failed_logon"]      = (win["event_id"] == 4625).astype(int)
win["is_process_create"]    = (win["event_id"] == 4688).astype(int)
win["is_privileged_logon"]  = (win["event_id"] == 4672).astype(int)
win["is_service_install"]   = (win["event_id"] == 7045).astype(int)
win["is_rdp_logon"]         = (win["logon_type"] == 10).astype(int)
win["is_network_logon"]     = (win["logon_type"] == 3).astype(int)

# Off-hours: computed relative to dataset's own activity distribution
#   Rather than assuming 8-18 is "normal", we find the hours that cover
#   the busiest 50% of all activity and treat the rest as off-hours.
hour_counts  = win["timestamp"].dt.hour.value_counts().sort_index()
busy_hours   = set(hour_counts[hour_counts >= hour_counts.median()].index)
win["is_off_hours"] = (~win["timestamp"].dt.hour.isin(busy_hours)).astype(int)

win_feat = win.groupby("source_ip").agg(
    win_total_events       = ("event_log_id",        "count"),
    win_unique_hosts       = ("hostname",             "nunique"),
    win_unique_users       = ("subject_username",     "nunique"),
    win_failed_logons      = ("is_failed_logon",      "sum"),
    win_process_creations  = ("is_process_create",    "sum"),
    win_privileged_logons  = ("is_privileged_logon",  "sum"),
    win_service_installs   = ("is_service_install",   "sum"),
    win_rdp_logons         = ("is_rdp_logon",         "sum"),
    win_network_logons     = ("is_network_logon",     "sum"),
    win_off_hours_events   = ("is_off_hours",         "sum"),
).reset_index()

# Ratio features normalise for volume — a busy server with 5 fails looks
# very different to an IP with 5 events all of which are fails.
n = win_feat["win_total_events"].clip(lower=1)
win_feat["win_fail_ratio"]       = win_feat["win_failed_logons"]     / n
win_feat["win_priv_ratio"]       = win_feat["win_privileged_logons"] / n
win_feat["win_process_ratio"]    = win_feat["win_process_creations"] / n
win_feat["win_off_hours_ratio"]  = win_feat["win_off_hours_events"]  / n
 
print(f"    → {len(win_feat):,} unique source IPs")

# ── 3. ZEEK FEATURES ─────────────────────────────────────────────────────────
print("\n[3] Engineering Zeek behavioral features...")
 
zeek["ts"] = pd.to_datetime(zeek["ts"])
 

# Continuous behavioral descriptors — no hardcoded port/hash assumptions
zeek["is_off_hours"]    = (~zeek["ts"].dt.hour.isin(busy_hours)).astype(int)
zeek["is_failed_conn"]  = (zeek["conn_state"].isin(["S0", "REJ"])).astype(int)
zeek["is_encrypted"]    = zeek["service"].isin(["ssl", "tls"]).astype(int)
zeek["bytes_ratio"]     = zeek["orig_bytes"] / zeek["resp_bytes"].clip(lower=1)
 
zeek_feat = zeek.groupby("id_orig_h").agg(
    zeek_total_conns       = ("log_id",       "count"),
    zeek_unique_dst_ips    = ("id_resp_h",    "nunique"),
    zeek_unique_dst_ports  = ("id_resp_p",    "nunique"),
    zeek_failed_conns      = ("is_failed_conn","sum"),
    zeek_encrypted_conns   = ("is_encrypted", "sum"),
    zeek_off_hours_conns   = ("is_off_hours", "sum"),
    zeek_mean_duration     = ("duration",     "mean"),
    zeek_mean_orig_bytes   = ("orig_bytes",   "mean"),
    zeek_mean_resp_bytes   = ("resp_bytes",   "mean"),
    zeek_total_orig_bytes  = ("orig_bytes",   "sum"),
    zeek_mean_bytes_ratio  = ("bytes_ratio",  "mean"),
    zeek_mean_orig_pkts    = ("orig_pkts",    "mean"),
).reset_index().rename(columns={"id_orig_h": "source_ip"})
 
n = zeek_feat["zeek_total_conns"].clip(lower=1)
zeek_feat["zeek_fail_ratio"]       = zeek_feat["zeek_failed_conns"]    / n
zeek_feat["zeek_encrypted_ratio"]  = zeek_feat["zeek_encrypted_conns"] / n
zeek_feat["zeek_off_hours_ratio"]  = zeek_feat["zeek_off_hours_conns"] / n
zeek_feat["zeek_dst_diversity"]    = zeek_feat["zeek_unique_dst_ports"] / zeek_feat["zeek_unique_dst_ips"].clip(lower=1)
 
print(f"    → {len(zeek_feat):,} unique source IPs")

# ── 4. MERGE ─────────────────────────────────────────────────────────────────
print("\n[4] Merging feature tables...")
combined = pd.merge(win_feat, zeek_feat, on="source_ip", how="outer").fillna(0)
print(f"    → {len(combined):,} unique IPs with combined features")
 

# ── 5. SCALE + ISOLATION FOREST ──────────────────────────────────────────────
print("\n[5] Scaling features and training Isolation Forest...")
 
FEATURE_COLS = [
    # Windows behavioral
    "win_total_events",      "win_unique_hosts",     "win_unique_users",
    "win_failed_logons",     "win_process_creations","win_privileged_logons",
    "win_service_installs",  "win_rdp_logons",        "win_network_logons",
    "win_fail_ratio",        "win_priv_ratio",        "win_process_ratio",
    "win_off_hours_ratio",
    # Zeek behavioral
    "zeek_total_conns",      "zeek_unique_dst_ips",  "zeek_unique_dst_ports",
    "zeek_failed_conns",     "zeek_encrypted_conns", "zeek_off_hours_conns",
    "zeek_mean_duration",    "zeek_mean_orig_bytes", "zeek_mean_resp_bytes",
    "zeek_total_orig_bytes", "zeek_mean_bytes_ratio","zeek_mean_orig_pkts",
    "zeek_fail_ratio",       "zeek_encrypted_ratio", "zeek_off_hours_ratio",
    "zeek_dst_diversity",
]
 
X_raw = combined[FEATURE_COLS].values
scaler = StandardScaler()
X      = scaler.fit_transform(X_raw)
 
model = IsolationForest(
    n_estimators=200,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
    n_jobs=-1,
)
model.fit(X)
 
raw_scores  = model.decision_function(X)   # more negative → more anomalous
predictions = model.predict(X)             # -1 = anomaly, 1 = normal

# Normalise to 0-1 threat score: 1 = most anomalous
score_min  = raw_scores.min()
score_max  = raw_scores.max()
threat_score = 1 - (raw_scores - score_min) / (score_max - score_min)
 
combined["threat_score"] = threat_score
combined["is_anomaly"]   = (predictions == -1).astype(int)
 

# ── 6. INFORMATIONAL INDICATORS (do not affect predictions) ──────────────────
# These help a human analyst understand *why* an IP scored high.
# They are purely descriptive — the model never sees them.
 
fail_thresh   = combined["win_fail_ratio"].quantile(0.90)
upload_thresh = combined["zeek_mean_bytes_ratio"].quantile(0.90)
port_thresh   = combined["zeek_unique_dst_ports"].quantile(0.90)
 
combined["ind_high_fail_ratio"]   = (combined["win_fail_ratio"]        > fail_thresh).astype(int)
combined["ind_high_upload_ratio"] = (combined["zeek_mean_bytes_ratio"] > upload_thresh).astype(int)
combined["ind_high_port_spread"]  = (combined["zeek_unique_dst_ports"] > port_thresh).astype(int)
 

# ── 7. RESULTS ───────────────────────────────────────────────────────────────
print("\n[6] Results")
print("-" * 60)
 
total   = len(combined)
flagged = int(combined["is_anomaly"].sum())
print(f"    Total unique IPs  : {total:,}")
print(f"    Anomalies flagged : {flagged:,}  ({flagged / total * 100:.1f}%)")
 
top = (combined[combined["is_anomaly"] == 1]
       .sort_values("threat_score", ascending=False)
       .head(TOP_N))
 
print(f"\n    Top {TOP_N} suspicious IPs (Isolation Forest decision):\n")
hdr = f"    {'IP':<20} {'Score':>6}  {'HighFail':>8}  {'HighUpload':>10}  {'PortSpread':>10}  {'WinFails':>8}  {'Conns':>6}"
print(hdr)
print("    " + "-" * (len(hdr) - 4))
for _, r in top.iterrows():
    print(
        f"    {r['source_ip']:<20} {r['threat_score']:>6.3f}"
        f"  {'YES' if r['ind_high_fail_ratio']   else '':>8}"
        f"  {'YES' if r['ind_high_upload_ratio'] else '':>10}"
        f"  {'YES' if r['ind_high_port_spread']  else '':>10}"
        f"  {int(r['win_failed_logons']):>8}"
        f"  {int(r['zeek_total_conns']):>6}"
    )
 

combined.sort_values("threat_score", ascending=False).to_csv(OUTPUT_CSV, index=False)
print(f"\n[7] Full results saved → {OUTPUT_CSV}")
print("=" * 60)
 

# ── 8. JA3 HASH FREQUENCY ANALYSIS (C2 Beacon Detection) ──────────────────────
print("\n[8] JA3 hash frequency analysis...")

# NOTE on adapting the original snippet to this notebook:
#   - zeek_conn_logs.csv has no 'flow_label' column (that field only exists on
#     netflow_records). The ground-truth column actually present here is
#     'is_anomaly', so the baseline is built from confirmed-normal Zeek rows.
#   - JA3 is empty/NaN for ~8% of rows (non-TLS traffic, per the data dictionary).
#     Those are left out of both the baseline AND the never-seen/rare flags below,
#     since a missing hash is not evidence of anything — flagging it would just
#     mislabel a chunk of legitimate UDP/ICMP/non-TLS traffic as suspicious.

KNOWN_C2_JA3 = "c7d1e3f2a4b6c8d0"  # documented IOC: appears in 89% of C2 beacons

has_hash = zeek["ja3_hash"].notna() & (zeek["ja3_hash"] != "")

if "is_anomaly" in zeek.columns:
    normal_ja3 = zeek.loc[has_hash & (zeek["is_anomaly"] == False), "ja3_hash"]
else:
    normal_ja3 = zeek.loc[has_hash, "ja3_hash"]

# Frequency of each hash within confirmed-normal traffic only
ja3_counts = normal_ja3.value_counts(normalize=True)

# Map each flow's JA3 hash to its frequency in normal traffic.
# Rare (or unseen) among normal traffic = suspicious; common = normal.
# Rows with no hash (non-TLS) get NaN here on purpose — handled separately below.
zeek["ja3_frequency_in_normal"] = zeek["ja3_hash"].map(ja3_counts)

# Log-transform because the distribution is very skewed —
# common hashes appear ~1000x more often than rare ones.
zeek["ja3_log_frequency"] = np.log1p(
    zeek["ja3_frequency_in_normal"].fillna(0) * 10000
)

# A hash that never appeared in normal traffic — restricted to rows that
# actually have a hash, so non-TLS traffic is never flagged by this rule.
zeek["ja3_never_seen_in_normal"] = (
    has_hash & zeek["ja3_frequency_in_normal"].isna()
).astype(int)

# A hash that appears in less than 0.01% of normal traffic
zeek["ja3_is_rare"] = (
    has_hash & (zeek["ja3_frequency_in_normal"].fillna(0) < 0.0001)
).astype(int)

# Explicit check for the documented C2 IOC hash. This is kept as its own
# independent signal rather than folded into the rarity score, because JA3
# fingerprints the TLS client library/config, not the application itself —
# a hash can be simultaneously 'common' overall (shared with benign apps using
# the same TLS stack) and still be the known-bad C2 hash. Rarity alone would
# miss that case; a direct match will not.
zeek["ja3_matches_known_c2"] = (zeek["ja3_hash"] == KNOWN_C2_JA3).astype(int)

print("    JA3 hash analysis (flow-level, zeek_conn_logs):")
print(f"      Unique JA3 hashes observed      : {zeek['ja3_hash'].nunique():,}")
print(f"      Never seen in normal traffic    : {zeek['ja3_never_seen_in_normal'].sum():,} flows")
print(f"      Rare in normal traffic (<0.01%) : {zeek['ja3_is_rare'].sum():,} flows")
print(f"      Matches known C2 IOC hash       : {zeek['ja3_matches_known_c2'].sum():,} flows")

# ── 8b. AGGREGATE JA3 SIGNAL PER SOURCE IP ─────────────────────────────────────
# Same groupby style/key (source_ip = id_orig_h) as the existing zeek_feat block,
# so this merges cleanly onto the same 'combined' table used for scoring.
ja3_feat = zeek.groupby("id_orig_h").agg(
    ja3_never_seen_conns = ("ja3_never_seen_in_normal", "sum"),
    ja3_rare_conns       = ("ja3_is_rare",              "sum"),
    ja3_known_c2_conns   = ("ja3_matches_known_c2",     "sum"),
    ja3_min_frequency    = ("ja3_frequency_in_normal",  "min"),
).reset_index().rename(columns={"id_orig_h": "source_ip"})

# Merge as additional informational columns on 'combined' — mirrors the existing
# section 6 pattern (indicators are descriptive only and do not feed back into
# FEATURE_COLS / the already-fitted Isolation Forest, so predictions,
# threat_score, and the printed Top-N table above are unaffected).
combined = combined.merge(ja3_feat, on="source_ip", how="left")
combined[["ja3_never_seen_conns", "ja3_rare_conns", "ja3_known_c2_conns"]] = (
    combined[["ja3_never_seen_conns", "ja3_rare_conns", "ja3_known_c2_conns"]].fillna(0)
)
combined["ind_ja3_c2_match"] = (combined["ja3_known_c2_conns"] > 0).astype(int)

# ── 8c. REPORT: SOURCE IPs WITH C2-LIKE JA3 ACTIVITY ───────────────────────────
ja3_flagged = (combined[(combined["ja3_known_c2_conns"] > 0) | (combined["ja3_rare_conns"] > 0)]
               .sort_values(["ja3_known_c2_conns", "ja3_rare_conns"], ascending=False)
               .head(TOP_N))

print(f"\n    Top IPs by JA3 C2 / rarity signal (informational — not a model input):\n")
hdr2 = f"    {'IP':<20} {'KnownC2Conns':>12}  {'RareConns':>10}  {'NeverSeenConns':>14}  {'ThreatScore':>11}"
print(hdr2)
print("    " + "-" * (len(hdr2) - 4))
for _, r in ja3_flagged.iterrows():
    print(
        f"    {r['source_ip']:<20} {int(r['ja3_known_c2_conns']):>12}"
        f"  {int(r['ja3_rare_conns']):>10}"
        f"  {int(r['ja3_never_seen_conns']):>14}"
        f"  {r['threat_score']:>11.3f}"
    )

# Saved separately so the original OUTPUT_CSV / pipeline result is left untouched.
combined.sort_values("threat_score", ascending=False).to_csv("../outputs/threat_results_with_ja3.csv", index=False)
print("\n[8] JA3-enriched results saved → threat_results_with_ja3.csv")





