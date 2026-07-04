"""
Behavior Agent - Hybrid Anomaly Detection Engine
GIBL AI/ML Hackathon 2026 | Track D | Sentinels of the Network

Multi-source security agent that analyzes:
  1. UEBA user behavior logs (Isolation Forest + Banking Rules)
  2. Windows Security Event Logs (Forensic Event Analysis)

Architecture:
  Layer 1 - ML Brain (Isolation Forest): Trains on 9 numerical UEBA features
  Layer 2 - Security Guard (Deterministic Rules): 9 UEBA rule checks
  Layer 3 - Windows Forensic Analyzer: 12 high-value Event ID checks
  Fusion:  final_score = max(ml_score, rule_score, windows_score)

References:
  - Data Dictionary S3.3 (windows_event_logs), S3.4 (ueba_user_behavior), S3.5 (host_profiles)
  - Data Dictionary S4 (Hidden Patterns #1, #2, #5)
  - Data Dictionary S5 (Attack Category Taxonomy)
  - Data Dictionary S6 (Network Segments, SWIFT CSP, Pumori CBS)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import time

def track_progress(iterable, desc="Processing", print_interval_percent=10):
    """
    A lightweight progress tracker that prints progress percentage and estimated time remaining (ETA).
    """
    total = len(iterable)
    if total == 0:
        return
    
    start_time = time.time()
    print_interval = max(1, total * print_interval_percent // 100)
    
    for idx, item in enumerate(iterable):
        yield item
        current_idx = idx + 1
        if current_idx % print_interval == 0 or current_idx == total:
            elapsed = time.time() - start_time
            speed = current_idx / elapsed if elapsed > 0 else 0
            remaining = total - current_idx
            eta = remaining / speed if speed > 0 else 0
            
            # Format ETA
            if eta >= 60:
                eta_str = f"{int(eta // 60)}m {int(eta % 60)}s"
            else:
                eta_str = f"{eta:.1f}s"
                
            percent = (current_idx / total) * 100
            print(f"      [{desc}] {current_idx:,}/{total:,} ({percent:.1f}%) | Speed: {speed:.0f} items/s | ETA: {eta_str}")


# ==============================================================================
#  Constants & Configuration
# ==============================================================================

# Risk tiers for event types - higher risk events contribute more to the score.
# Based on typical SOC analyst prioritization in banking environments.
EVENT_TYPE_RISK = {
    "FILE_ACCESS":      0.05,
    "DB_QUERY":         0.10,
    "EMAIL_SEND":       0.05,
    "SHARE_ACCESS":     0.10,
    "PRINT":            0.02,
    "REMOTE_LOGIN":     0.15,
    "PRIVILEGE_USE":    0.25,
    "SOFTWARE_INSTALL": 0.30,
    "USB_INSERT":       0.20,
    "LARGE_DOWNLOAD":   0.15,
}

# MITRE ATT&CK mapping for behavior anomalies.
# Each flag maps to a (tactic, technique_id) tuple.
BEHAVIOR_MITRE_MAP = {
    "off_hours":              ("Persistence",          "T1078"),
    "high_peer_deviation":    ("Valid Accounts",       "T1078"),
    "elevated_peer_deviation":("Valid Accounts",       "T1078"),
    "large_data_transfer":    ("Exfiltration",         "T1041"),
    "new_swift_resource":     ("Collection",           "T1005"),
    "new_resource":           ("Discovery",            "T1083"),
    "failed_access_spike":    ("Credential Access",    "T1110"),
    "failed_access_elevated": ("Credential Access",    "T1110"),
    "swift_off_hours":        ("Lateral Movement",     "T1021"),
    "unauthorized_pumori":    ("Collection",           "T1005"),
    "privilege_abuse":        ("Privilege Escalation",  "T1078"),
    "ml_anomaly":             ("Anomaly",              "T0000"),
    "swift_query_velocity":   ("Collection",           "T1005"),
}

# MITRE ATT&CK mapping for Windows event anomalies.
WINDOWS_MITRE_MAP = {
    "audit_log_cleared":      ("Defense Evasion",      "T1562.001"),
    "credential_dump":        ("Credential Access",    "T1003.001"),
    "new_service_atm":        ("Persistence",          "T1543.003"),
    "new_service":            ("Persistence",          "T1543.003"),
    "priv_escalation":        ("Privilege Escalation", "T1078"),
    "explicit_credential":    ("Lateral Movement",     "T1021"),
    "brute_force":            ("Credential Access",    "T1110"),
    "account_lockout":        ("Credential Access",    "T1110"),
    "scheduled_task":         ("Persistence",          "T1053.005"),
    "user_created":           ("Persistence",          "T1136.001"),
    "kerberoasting":          ("Credential Access",    "T1558.003"),
    "share_access_bulk":      ("Lateral Movement",     "T1021.002"),
    "suspicious_process":     ("Execution",            "T1059"),
    "off_hours_logon":        ("Persistence",          "T1078"),
}

# Feature columns used by the Isolation Forest model.
FEATURE_COLUMNS = [
    "bytes_transferred",
    "duration_sec",
    "failed_attempts_prior_1h",
    "peer_group_deviation_score",
    "is_off_hours_num",
    "is_new_resource_num",
    "hour_of_day",
    "day_of_week",
    "event_type_risk",
]

# Default list of accounts authorized to query the Pumori CBS database.
# Any other account querying Pumori triggers an immediate CRITICAL alert.
DEFAULT_PUMORI_WHITELIST = [
    "srv_pumori_app",
    "pumori_batch",
    "admin_db_sync",
    "cbs_service",
    "pumori_reporting",
]

# Known admin accounts that are authorized for privilege escalation.
# Event 4672 from any account NOT in this list is flagged.
DEFAULT_ADMIN_ACCOUNTS = [
    "admin_01", "admin_02", "admin_03",
    "svc_backup", "svc_monitor", "svc_antivirus",
    "svc_wsus", "svc_sccm",
]

# Suspicious process names for Event 4688 checks.
# These indicate credential dumping, masquerading malware, or attack tools.
SUSPICIOUS_PROCESSES = {
    "lsass.exe":            ("credential_dump",    "T1003.001", 0.95),
    "mimikatz.exe":         ("credential_dump",    "T1003.001", 1.00),
    "procdump.exe":         ("credential_dump",    "T1003.001", 0.90),
    "DefenderHelper.exe":   ("new_service",        "T1543.003", 0.95),
    "WindowsUpdateSvc.exe": ("new_service",        "T1543.003", 0.95),
    "NetSvc64.exe":         ("new_service",        "T1543.003", 0.95),
    "SysMonitor32.exe":     ("new_service",        "T1543.003", 0.95),
}

# Processes that are suspicious ONLY when spawned by unexpected parents.
SUSPICIOUS_PARENT_COMBOS = {
    ("powershell.exe", "winword.exe"):  ("suspicious_process", "T1059.001", 0.90),
    ("powershell.exe", "excel.exe"):    ("suspicious_process", "T1059.001", 0.90),
    ("cmd.exe",        "winword.exe"):  ("suspicious_process", "T1059.003", 0.85),
    ("wscript.exe",    "explorer.exe"): ("suspicious_process", "T1059.005", 0.80),
}


# ==============================================================================
#  BehaviorAgent Class
# ==============================================================================

class BehaviorAgent:
    """
    Hybrid Behavior Agent for multi-source anomaly detection.
    
    Processes UEBA logs (ML + Rules) and Windows Security Events (Forensic Analysis)
    to produce a unified behavior_score per source IP for the Correlation Agent.
    """

    def __init__(self, pumori_whitelist=None, admin_accounts=None,
                 contamination=0.02, n_estimators=200, random_state=42):
        self.pumori_whitelist = [
            u.lower() for u in (pumori_whitelist or DEFAULT_PUMORI_WHITELIST)
        ]
        self.admin_accounts = [
            u.lower() for u in (admin_accounts or DEFAULT_ADMIN_ACCOUNTS)
        ]
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        # ML components (initialized during fit)
        self.model = None
        self.scaler = None
        self.is_fitted = False

        # Host context (loaded separately)
        self.host_profiles = None
        self.hostname_to_segment = {}
        self.hostname_to_ip = {}
        self.ip_to_hostname = {}
        self.hostname_to_criticality = {}
        self.honeypot_ips = set()
        self.honeypot_hosts = set()

        # Per-user behavioral profiles (built during fit, updated during scoring)
        self.user_profiles = defaultdict(lambda: {
            "bytes_history": [],
            "peer_scores": [],
            "login_hours": [],
            "event_count": 0,
        })

        # Windows event analysis results (populated by analyze_windows_events)
        self.windows_results = []

    # --------------------------------------------------------------------------
    #  Host Context Loading
    # --------------------------------------------------------------------------

    def load_host_context(self, host_profiles_path_or_df):
        """Load host_profiles.csv to understand network segments and criticality."""
        if isinstance(host_profiles_path_or_df, str):
            self.host_profiles = pd.read_csv(host_profiles_path_or_df)
        else:
            self.host_profiles = host_profiles_path_or_df.copy()

        # Build lookup dictionaries for fast access during scoring
        for _, row in self.host_profiles.iterrows():
            hostname = row["hostname"]
            ip = row["ip_address"]
            self.hostname_to_segment[hostname] = row.get("segment", "UNKNOWN")
            self.hostname_to_ip[hostname] = ip
            self.ip_to_hostname[ip] = hostname
            self.hostname_to_criticality[hostname] = row.get("criticality", "MEDIUM")
            if row.get("is_honeypot", False):
                self.honeypot_ips.add(ip)
                self.honeypot_hosts.add(hostname)

        print(f"    [BehaviorAgent] Loaded context for {len(self.host_profiles)} hosts")
        print(f"    [BehaviorAgent] Segments: {set(self.hostname_to_segment.values())}")
        print(f"    [BehaviorAgent] Honeypots: {len(self.honeypot_ips)}")

    # --------------------------------------------------------------------------
    #  UEBA Feature Extraction
    # --------------------------------------------------------------------------

    def _prepare_features(self, df):
        """Extract and engineer the 9 features for the Isolation Forest model."""
        features = pd.DataFrame(index=df.index)

        # Direct numerical columns
        features["bytes_transferred"] = pd.to_numeric(
            df["bytes_transferred"], errors="coerce"
        ).fillna(0)
        features["duration_sec"] = pd.to_numeric(
            df["duration_sec"], errors="coerce"
        ).fillna(0)
        features["failed_attempts_prior_1h"] = pd.to_numeric(
            df["failed_attempts_prior_1h"], errors="coerce"
        ).fillna(0)
        features["peer_group_deviation_score"] = pd.to_numeric(
            df["peer_group_deviation_score"], errors="coerce"
        ).fillna(0)

        # Convert boolean columns to numeric (0/1)
        features["is_off_hours_num"] = df["is_off_hours"].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int)
        features["is_new_resource_num"] = df["is_new_resource"].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int)

        # Temporal features from timestamp
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce")
        features["hour_of_day"] = timestamps.dt.hour.fillna(12).astype(int)
        features["day_of_week"] = timestamps.dt.dayofweek.fillna(0).astype(int)

        # Event type risk score
        features["event_type_risk"] = df["event_type"].map(
            EVENT_TYPE_RISK
        ).fillna(0.05)

        return features[FEATURE_COLUMNS]

    # --------------------------------------------------------------------------
    #  Model Training
    # --------------------------------------------------------------------------

    def fit(self, ueba_df):
        """Train the Isolation Forest model on UEBA data and build user profiles."""
        print(f"    [BehaviorAgent] Training on {len(ueba_df):,} events...")

        # Step 1: Extract features
        X = self._prepare_features(ueba_df)
        print(f"    [BehaviorAgent] Feature matrix: {X.shape[0]} rows x {X.shape[1]} features")

        # Step 2: Scale features (StandardScaler normalizes to mean=0, std=1)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Step 3: Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,  # Use all CPU cores
        )
        self.model.fit(X_scaled)
        self.is_fitted = True
        print(f"    [BehaviorAgent] Isolation Forest trained "
              f"({self.n_estimators} trees, contamination={self.contamination})")

        # Step 4: Calibrate score range using training data
        train_scores = self.model.score_samples(X_scaled)
        self.score_min = float(np.percentile(train_scores, 1))
        self.score_max = float(np.percentile(train_scores, 99))
        print(f"    [BehaviorAgent] Score calibration: min={self.score_min:.4f}, max={self.score_max:.4f}")

        # Step 5: Build per-user behavioral profiles from training data
        records = ueba_df[["username", "bytes_transferred", "peer_group_deviation_score", "timestamp"]].to_dict("records")
        for row in records:
            username = str(row.get("username", "unknown"))
            profile = self.user_profiles[username]
            profile["bytes_history"].append(int(row.get("bytes_transferred", 0)))
            profile["peer_scores"].append(float(row.get("peer_group_deviation_score", 0)))
            ts = pd.to_datetime(row.get("timestamp", "2026-01-01"), errors="coerce")
            if pd.notna(ts):
                profile["login_hours"].append(ts.hour)
            profile["event_count"] += 1

        print(f"    [BehaviorAgent] Built profiles for {len(self.user_profiles)} users")
        return self

    # --------------------------------------------------------------------------
    #  Layer 1: ML Brain (Isolation Forest Scoring)
    # --------------------------------------------------------------------------

    def _ml_score(self, features_row):
        """Get the Isolation Forest anomaly score for a single event (0.0-1.0)."""
        if not self.is_fitted:
            return 0.0

        X = features_row[FEATURE_COLUMNS].values.reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        raw_score = self.model.score_samples(X_scaled)[0]

        # Convert using calibrated range from training data.
        score_range = self.score_max - self.score_min
        if score_range == 0:
            score_range = 1.0
        score = float(np.clip((self.score_max - raw_score) / score_range, 0.0, 1.0))
        return round(score, 4)

    def _ml_score_batch(self, features_df):
        """Score all events at once (vectorized) — avoids per-row joblib overhead."""
        if not self.is_fitted:
            return np.zeros(len(features_df))

        X = features_df[FEATURE_COLUMNS].values
        X_scaled = self.scaler.transform(X)
        raw_scores = self.model.score_samples(X_scaled)

        score_range = self.score_max - self.score_min
        if score_range == 0:
            score_range = 1.0
        scores = np.clip((self.score_max - raw_scores) / score_range, 0.0, 1.0)
        return np.round(scores, 4)
    
    # --------------------------------------------------------------------------
    #  Layer 2: Security Guard (UEBA Rule Checks)
    # --------------------------------------------------------------------------

    def _rule_checks(self, event):
        """Apply deterministic banking security rules to a single UEBA event."""
        flags = []
        mitre = []
        rule_score = 0.0

        username = str(event.get("username", "")).lower()
        hostname = str(event.get("hostname", ""))
        resource = str(event.get("resource_accessed", "")).lower()
        event_type = str(event.get("event_type", ""))

        # Service accounts / batch accounts are expected to run off-hours, so we ignore off-hours for them
        is_service_account = username.startswith("srv_") or username.startswith("svc_")

        # Check 1: Off-Hours Access
        # Hidden Pattern #1: 67% of C2 beacons occur Saturday 03:00-05:00 NPT
        is_off_hours = event.get("is_off_hours", False)
        if is_off_hours in (True, "True", 1, "1") and not is_service_account:
            rule_score += 0.08
            flags.append("off_hours")
            mitre.append(BEHAVIOR_MITRE_MAP["off_hours"])

            # Extra penalty for weekend early-morning (Saturday 03:00-05:00)
            ts = pd.to_datetime(event.get("timestamp", ""), errors="coerce")
            if pd.notna(ts) and ts.dayofweek == 5 and 3 <= ts.hour <= 5:
                rule_score += 0.10  # additional weekend penalty
                flags.append("weekend_early_morning")

        # Check 2: Peer Group Deviation
        # Hidden Pattern #5: compromised users consistently > 0.65
        peer_score = float(event.get("peer_group_deviation_score", 0.0))
        if peer_score >= 0.80:
            rule_score += 0.25
            flags.append("high_peer_deviation")
            mitre.append(BEHAVIOR_MITRE_MAP["high_peer_deviation"])
        elif peer_score >= 0.65:
            rule_score += 0.10
            flags.append("elevated_peer_deviation")
            mitre.append(BEHAVIOR_MITRE_MAP["elevated_peer_deviation"])

        # Check 3: Large Data Transfer (Hidden Pattern from data dictionary)
        bytes_transferred = int(event.get("bytes_transferred", 0))
        profile = self.user_profiles.get(username, {})
        bytes_history = profile.get("bytes_history", [])
        avg_bytes = float(np.mean(bytes_history)) if bytes_history else 0.0

        if bytes_transferred > 100_000_000 and avg_bytes < 5_000_000:
            rule_score += 0.35
            flags.append("large_data_transfer")
            mitre.append(BEHAVIOR_MITRE_MAP["large_data_transfer"])
        elif bytes_transferred > 50_000_000 and avg_bytes < 5_000_000:
            rule_score += 0.15
            flags.append("large_data_transfer")

        # Check 4: New Resource Access
        is_new = event.get("is_new_resource", False)
        if is_new in (True, "True", 1, "1"):
            if "swift_mt" in resource or "swift" in resource:
                rule_score += 0.20
                flags.append("new_swift_resource")
                mitre.append(BEHAVIOR_MITRE_MAP["new_swift_resource"])
            else:
                rule_score += 0.05
                flags.append("new_resource")

        # Check 5: Failed Access Spike
        failed = int(event.get("failed_attempts_prior_1h", 0))
        if failed >= 10:
            rule_score += 0.30
            flags.append("failed_access_spike")
            mitre.append(BEHAVIOR_MITRE_MAP["failed_access_spike"])
        elif failed >= 5:
            rule_score += 0.10
            flags.append("failed_access_elevated")
            mitre.append(BEHAVIOR_MITRE_MAP["failed_access_elevated"])

        # Check 6: SWIFT Segment Off-Hours Access
        segment = self.hostname_to_segment.get(hostname, "")
        if segment == "SWIFT" and is_off_hours in (True, "True", 1, "1") and not is_service_account:
            rule_score += 0.30
            if "swift_off_hours" not in flags:
                flags.append("swift_off_hours")
                mitre.append(BEHAVIOR_MITRE_MAP["swift_off_hours"])

        # Check 7: Pumori Database Unauthorized Access
        if "pumori" in resource:
            if username not in self.pumori_whitelist:
                rule_score += 0.55
                flags.append("unauthorized_pumori")
                mitre.append(BEHAVIOR_MITRE_MAP["unauthorized_pumori"])

        # Check 8: High-Risk Event Types (Disabled to prevent false alarms on benign activity)
        # if event_type in ("USB_INSERT", "SOFTWARE_INSTALL", "PRIVILEGE_USE"):
        #     risk = EVENT_TYPE_RISK.get(event_type, 0.05)
        #     rule_score += risk
        #     if event_type == "PRIVILEGE_USE":
        #         flags.append("privilege_abuse")
        #         mitre.append(BEHAVIOR_MITRE_MAP["privilege_abuse"])

        # Check 9: Honeypot Contact (dest check)
        if hostname in self.honeypot_hosts:
            rule_score += 0.60
            flags.append("honeypot_contact")

        return min(rule_score, 1.0), flags, mitre

    # --------------------------------------------------------------------------
    #  UEBA Event Scoring (ML + Rules combined)
    # --------------------------------------------------------------------------

    def score_event(self, event, features_row=None, ml_score=None):
        """Score a single UEBA event using both ML and rules."""
        # Layer 1: ML Brain
        if ml_score is None:
            ml_score = 0.0
            if self.is_fitted and features_row is not None:
                ml_score = self._ml_score(features_row)

        # Layer 2: Security Guard
        rule_score, flags, mitre = self._rule_checks(event)

        # Hybrid combination: max with agreement boost and dampening
        final_score = max(ml_score, rule_score)
        
        # Boost when both ML and rules agree on strong anomaly
        if ml_score >= 0.55 and rule_score >= 0.55:
            final_score = min(final_score + 0.10, 1.0)
        # Dampen ML-only anomalies based on rule support
        elif rule_score < 0.10:
            final_score = ml_score * 0.50
        elif rule_score < 0.20:
            final_score = ml_score * 0.70
        elif rule_score < 0.35:
            final_score = ml_score * 0.85

        # If ML score is high but rules didn't fire strongly, note it
        if ml_score > 0.70 and rule_score < 0.50:
            flags.append("ml_anomaly")
            mitre.append(BEHAVIOR_MITRE_MAP["ml_anomaly"])

        # Resolve source_ip
        hostname = str(event.get("hostname", "unknown"))
        username = str(event.get("username", "unknown"))
        source_ip = str(event.get("source_ip", ""))
        if not source_ip:
            source_ip = self.hostname_to_ip.get(hostname, "")

        return {
            "entity": f"{username}@{hostname}",
            "agent": "behavior",
            "source": "ueba",
            "score": round(min(final_score, 1.0), 4),
            "ml_score": round(ml_score, 4),
            "rule_score": round(min(rule_score, 1.0), 4),
            "flags": flags,
            "mitre": mitre,
            "source_ip": source_ip,
            "username": username,
            "hostname": hostname,
            "timestamp": str(event.get("timestamp", "")),
        }

    def score_batch(self, ueba_df):
        """Score all UEBA events in a DataFrame."""
        print(f"    [BehaviorAgent] Scoring {len(ueba_df):,} UEBA events...")

        # Step 1: Pre-compute all features in one vectorized pass
        features = self._prepare_features(ueba_df)

        # Step 2: Batch compute all ML scores at once if model is fitted
        ml_scores = np.zeros(len(ueba_df))
        if self.is_fitted:
            X = features[FEATURE_COLUMNS].values
            X_scaled = self.scaler.transform(X)
            raw_scores = self.model.score_samples(X_scaled)
            score_range = self.score_max - self.score_min
            if score_range == 0:
                score_range = 1.0
            # Vectorized calibration and clipping
            ml_scores = np.clip((self.score_max - raw_scores) / score_range, 0.0, 1.0)
            ml_scores = np.round(ml_scores, 4)

        # Step 3: Iterate fast using list-of-dict records
        records = ueba_df.to_dict("records")
        results = []

        for idx, event in enumerate(track_progress(records, desc="Scoring UEBA", print_interval_percent=10)):
            # Resolve Layers
            rule_score, flags, mitre = self._rule_checks(event)
            ml_score = float(ml_scores[idx])
            final_score = max(ml_score, rule_score)
            
            # Boost when both ML and rules agree on strong anomaly
            if ml_score >= 0.55 and rule_score >= 0.55:
                final_score = min(final_score + 0.10, 1.0)
            # Dampen ML-only anomalies based on rule support
            elif rule_score < 0.10:
                final_score = ml_score * 0.50
            elif rule_score < 0.20:
                final_score = ml_score * 0.70
            elif rule_score < 0.35:
                final_score = ml_score * 0.85

            if ml_score > 0.70 and rule_score < 0.50:
                flags.append("ml_anomaly")
                mitre.append(BEHAVIOR_MITRE_MAP["ml_anomaly"])

            hostname = str(event.get("hostname", "unknown"))
            username = str(event.get("username", "unknown"))
            source_ip = str(event.get("source_ip", ""))
            if not source_ip:
                source_ip = self.hostname_to_ip.get(hostname, "")

            result = {
                "entity": f"{username}@{hostname}",
                "agent": "behavior",
                "source": "ueba",
                "score": round(min(final_score, 1.0), 4),
                "ml_score": ml_score,
                "rule_score": round(min(rule_score, 1.0), 4),
                "flags": flags,
                "mitre": mitre,
                "source_ip": source_ip,
                "username": username,
                "hostname": hostname,
                "timestamp": str(event.get("timestamp", "")),
            }
            results.append(result)

            # Update user profile with this event
            username_lower = username.lower()
            profile = self.user_profiles[username_lower]
            profile["bytes_history"].append(int(event.get("bytes_transferred", 0)))
            profile["peer_scores"].append(float(event.get("peer_group_deviation_score", 0)))
            profile["event_count"] += 1

        # Print scoring summary
        scores = [r["score"] for r in results]
        n_flagged = sum(1 for s in scores if s >= 0.75)
        print(f"    [BehaviorAgent] UEBA scoring complete:")
        print(f"      Mean score  : {np.mean(scores):.4f}")
        print(f"      Max score   : {np.max(scores):.4f}")
        print(f"      Flagged     : {n_flagged:,} events (score >= 0.75)")

        return results

    # --------------------------------------------------------------------------
    #  SWIFT Query Velocity Check (Hidden Pattern #2)
    # --------------------------------------------------------------------------

    def check_swift_query_velocity(self, ueba_df):
        """
        Hidden Pattern #2: SWIFT subnet DB queries > 400 in any 2-minute
        window = SWIFT fraud precursor.
        
        Returns a list of result dicts for any user who triggers this check.
        """
        print("    [BehaviorAgent] Checking SWIFT query velocity (Hidden Pattern #2)...")

        # Get SWIFT hostnames from host context
        swift_hostnames = {h for h, s in self.hostname_to_segment.items() if s == "SWIFT"}

        # Filter for DB_QUERY events on SWIFT hosts or accessing SWIFT resources
        swift_mask = (
            (ueba_df["hostname"].isin(swift_hostnames)) |
            (ueba_df["resource_accessed"].str.contains("SWIFT", case=False, na=False))
        ) & (ueba_df["event_type"] == "DB_QUERY")

        swift_queries = ueba_df[swift_mask].copy()

        if swift_queries.empty:
            print("      No SWIFT DB queries found.")
            return []

        swift_queries["timestamp_dt"] = pd.to_datetime(swift_queries["timestamp"], errors="coerce")
        swift_queries = swift_queries.sort_values("timestamp_dt")

        velocity_results = []
        # Group by username and check 2-minute rolling window counts
        for username, group in swift_queries.groupby("username"):
            if len(group) < 400:
                continue  # skip users with very few queries

            group = group.sort_values("timestamp_dt")
            timestamps = group["timestamp_dt"].values

            # O(N) sliding window using two pointers
            left = 0
            for right in range(len(timestamps)):
                # Shrink window from left if it exceeds 2 minutes (120 seconds)
                while (timestamps[right] - timestamps[left]) > np.timedelta64(2, "m"):
                    left += 1

                # Number of elements in current window is (right - left + 1)
                count_in_window = right - left + 1
                if count_in_window > 400:
                    # SWIFT fraud precursor detected!
                    hostname = group.iloc[right].get("hostname", "unknown")
                    source_ip = str(group.iloc[right].get("source_ip", ""))
                    if not source_ip:
                        source_ip = self.hostname_to_ip.get(hostname, "")

                    velocity_results.append({
                        "entity": f"{username}@{hostname}",
                        "agent": "behavior",
                        "source": "ueba_velocity",
                        "score": 1.0,
                        "ml_score": 0.0,
                        "rule_score": 1.0,
                        "flags": ["swift_query_velocity"],
                        "mitre": [BEHAVIOR_MITRE_MAP["swift_query_velocity"]],
                        "source_ip": source_ip,
                        "username": username,
                        "hostname": hostname,
                        "timestamp": str(pd.Timestamp(timestamps[right])),
                    })
                    print(f"      CRITICAL: {username} made {count_in_window} SWIFT "
                           f"queries in 2 minutes at {pd.Timestamp(timestamps[right])}")
                    break  # one detection per user is enough

        print(f"      SWIFT velocity violations: {len(velocity_results)}")
        return velocity_results

    # --------------------------------------------------------------------------
    #  Layer 3: Windows Event Forensic Analyzer
    # --------------------------------------------------------------------------

    def analyze_windows_events(self, windows_df):
        """
        Analyze Windows Security Event Logs for all 12 high-value Event IDs
        from Data Dictionary S3.3.1.
        
        Parameters
        ----------
        windows_df : pd.DataFrame
            Cleaned (deduplicated, IP-imputed) Windows event logs.
            
        Returns
        -------
        list of dict
            One result dict per detected anomaly.
        """
        print(f"    [BehaviorAgent] Analyzing {len(windows_df):,} Windows events...")

        results = []
        # Track failed logins per user for brute force detection
        failed_logins = defaultdict(list)  # username -> list of timestamps
        # Track share access per user for ransomware staging detection
        share_access_counts = defaultdict(int)

        # Optimize by converting to dict records instead of iterrows
        # Vectorized pre-parsing of timestamps to avoid slow parsing in loop
        if "timestamp_dt" not in windows_df.columns:
            windows_df["timestamp_dt"] = pd.to_datetime(windows_df["timestamp"], errors="coerce")
        records = windows_df.to_dict("records")
        for event in track_progress(records, desc="Analyzing Windows Logs", print_interval_percent=10):
            event_id = int(event.get("event_id", 0))
            hostname = str(event.get("hostname", ""))
            subject_user = str(event.get("subject_username", "")).lower()
            target_user = str(event.get("target_username", "")).lower()
            process_name = str(event.get("process_name", "")).lower()
            parent_process = str(event.get("parent_process", "")).lower()
            source_ip = str(event.get("source_ip", ""))
            timestamp = str(event.get("timestamp", ""))
            logon_type = event.get("logon_type", None)
            segment = self.hostname_to_segment.get(hostname, "UNKNOWN")

            # Resolve source_ip from hostname if empty
            resolved_ip = source_ip if source_ip and source_ip != "LOCAL" else self.hostname_to_ip.get(hostname, source_ip)

            result = None

            # ---- Event 1102: Audit Log Cleared (CRITICAL) ----
            if event_id == 1102:
                result = {
                    "score": 1.0,
                    "flags": ["audit_log_cleared"],
                    "mitre": [WINDOWS_MITRE_MAP["audit_log_cleared"]],
                    "attack_category": "INSIDER_THREAT",
                }

            # ---- Event 7045: New Service Installed ----
            elif event_id == 7045:
                if hostname.startswith("ATM-"):
                    # ATM Jackpotting - new service on ATM is always critical
                    result = {
                        "score": 1.0,
                        "flags": ["new_service_atm"],
                        "mitre": [WINDOWS_MITRE_MAP["new_service_atm"]],
                        "attack_category": "ATM_JACKPOTTING",
                    }
                elif process_name in SUSPICIOUS_PROCESSES:
                    proc_info = SUSPICIOUS_PROCESSES[process_name]
                    result = {
                        "score": proc_info[2],
                        "flags": ["new_service"],
                        "mitre": [WINDOWS_MITRE_MAP["new_service"]],
                        "attack_category": "INSIDER_THREAT",
                    }
                else:
                    result = {
                        "score": 0.45,
                        "flags": ["new_service"],
                        "mitre": [WINDOWS_MITRE_MAP["new_service"]],
                        "attack_category": "INSIDER_THREAT",
                    }

            # ---- Event 4688: Process Created ----
            elif event_id == 4688:
                if process_name in SUSPICIOUS_PROCESSES:
                    proc_info = SUSPICIOUS_PROCESSES[process_name]
                    result = {
                        "score": proc_info[2],
                        "flags": [proc_info[0]],
                        "mitre": [WINDOWS_MITRE_MAP.get(proc_info[0], ("Execution", proc_info[1]))],
                        "attack_category": "INSIDER_THREAT",
                    }
                # Check suspicious parent-child process combos
                combo = (process_name, parent_process)
                if combo in SUSPICIOUS_PARENT_COMBOS:
                    combo_info = SUSPICIOUS_PARENT_COMBOS[combo]
                    result = {
                        "score": combo_info[2],
                        "flags": [combo_info[0]],
                        "mitre": [WINDOWS_MITRE_MAP.get(combo_info[0], ("Execution", combo_info[1]))],
                        "attack_category": "INSIDER_THREAT",
                    }

            # ---- Event 4672: Special Privileges Assigned ----
            elif event_id == 4672:
                if subject_user not in self.admin_accounts and not subject_user.endswith("$"):
                    ts = event.get("timestamp_dt")
                    is_off = False
                    if pd.notna(ts):
                        is_off = (ts.hour < 8 or ts.hour >= 18 or ts.dayofweek >= 5)
                    score = 0.80 if is_off else 0.50
                    result = {
                        "score": score,
                        "flags": ["priv_escalation"],
                        "mitre": [WINDOWS_MITRE_MAP["priv_escalation"]],
                        "attack_category": "INSIDER_THREAT",
                    }

            # ---- Event 4648: Explicit Credential Use (Lateral Movement) ----
            elif event_id == 4648:
                ts_4648 = event.get("timestamp_dt")
                is_off_4648 = False
                if pd.notna(ts_4648):
                    is_off_4648 = (ts_4648.hour < 8 or ts_4648.hour >= 18 or ts_4648.dayofweek >= 5)
                score_4648 = 0.80 if is_off_4648 else 0.50
                result = {
                    "score": score_4648,
                    "flags": ["explicit_credential"],
                    "mitre": [WINDOWS_MITRE_MAP["explicit_credential"]],
                    "attack_category": "LATERAL_MOVEMENT",
                }

            # ---- Event 4625: Failed Logon (Brute Force tracking) ----
            elif event_id == 4625:
                ts = event.get("timestamp_dt")
                if pd.notna(ts):
                    failed_logins[target_user].append(ts)

                    # Clean history older than 5 minutes
                    five_mins_ago = ts - pd.Timedelta(minutes=5)
                    failed_logins[target_user] = [
                        t for t in failed_logins[target_user] if t > five_mins_ago
                    ]

                    n_failures = len(failed_logins[target_user])
                    if n_failures >= 10:
                        # Check velocity
                        time_span = (failed_logins[target_user][-1] - 
                                     failed_logins[target_user][0]).total_seconds()
                        if time_span < 5:
                            # Automated attack (very fast attempts)
                            result = {
                                "score": 0.90,
                                "flags": ["brute_force"],
                                "mitre": [WINDOWS_MITRE_MAP["brute_force"]],
                                "attack_category": "BRUTE_FORCE",
                            }
                        else:
                            # Slower but still exceeds threshold
                            result = {
                                "score": 0.70,
                                "flags": ["brute_force"],
                                "mitre": [WINDOWS_MITRE_MAP["brute_force"]],
                                "attack_category": "BRUTE_FORCE",
                            }
                    else:
                        # Individual failed logons during off hours targeting admin/sql/svc accounts indicate kerberoasting
                        is_off = (ts.hour < 8 or ts.hour >= 18 or ts.dayofweek >= 5)
                        is_high_value = any(pat in target_user for pat in ("admin", "sql", "db", "svc"))
                        if is_off and is_high_value:
                            result = {
                                "score": 0.80,
                                "flags": ["kerberoasting"],
                                "mitre": [WINDOWS_MITRE_MAP["kerberoasting"]],
                                "attack_category": "BRUTE_FORCE",
                            }

            # ---- Event 4740: Account Locked Out ----
            elif event_id == 4740:
                result = {
                    "score": 0.50,
                    "flags": ["account_lockout"],
                    "mitre": [WINDOWS_MITRE_MAP["account_lockout"]],
                    "attack_category": "BRUTE_FORCE",
                }

            # ---- Event 4698: Scheduled Task Created ----
            elif event_id == 4698:
                ts = event.get("timestamp_dt")
                is_off = False
                if pd.notna(ts):
                    is_off = (ts.hour < 8 or ts.hour >= 18 or ts.dayofweek >= 5)
                score = 0.80 if (is_off or segment in ("CORE_BANKING", "SWIFT")) else 0.50
                result = {
                    "score": score,
                    "flags": ["scheduled_task"],
                    "mitre": [WINDOWS_MITRE_MAP["scheduled_task"]],
                    "attack_category": "INSIDER_THREAT",
                }

            # ---- Event 4720: User Account Created ----
            elif event_id == 4720:
                ts = event.get("timestamp_dt")
                is_off = False
                if pd.notna(ts):
                    is_off = (ts.hour < 8 or ts.hour >= 18 or ts.dayofweek >= 5)
                score = 0.80 if is_off else 0.50
                result = {
                    "score": score,
                    "flags": ["user_created"],
                    "mitre": [WINDOWS_MITRE_MAP["user_created"]],
                    "attack_category": "INSIDER_THREAT",
                }

            # ---- Event 4771: Kerberos Pre-Auth Failed ----
            elif event_id == 4771:
                ts = event.get("timestamp_dt")
                if pd.notna(ts):
                    is_off = (ts.hour < 8 or ts.hour >= 18 or ts.dayofweek >= 5)
                    is_high_value = any(pat in target_user for pat in ("admin", "sql", "db", "svc"))
                    if is_off and is_high_value:
                        result = {
                            "score": 0.80,
                            "flags": ["kerberoasting"],
                            "mitre": [WINDOWS_MITRE_MAP["kerberoasting"]],
                            "attack_category": "BRUTE_FORCE",
                        }

            # ---- Event 4769: Kerberos Service Ticket Requested (Kerberoasting) ----
            elif event_id == 4769:
                ts = event.get("timestamp_dt")
                if pd.notna(ts):
                    is_off = (ts.hour < 8 or ts.hour >= 18 or ts.dayofweek >= 5)
                    is_high_value = any(pat in target_user or pat in subject_user for pat in ("admin", "sql", "db", "svc"))
                    if is_off and is_high_value:
                        result = {
                            "score": 0.80,
                            "flags": ["kerberoasting"],
                            "mitre": [WINDOWS_MITRE_MAP["kerberoasting"]],
                            "attack_category": "BRUTE_FORCE",
                        }

            # ---- Event 5140: Network Share Accessed ----
            elif event_id == 5140:
                share_access_counts[subject_user] += 1
                if share_access_counts[subject_user] >= 50:
                    result = {
                        "score": 0.75,
                        "flags": ["share_access_bulk"],
                        "mitre": [WINDOWS_MITRE_MAP["share_access_bulk"]],
                        "attack_category": "RANSOMWARE_STAGING",
                    }

            # ---- Event 4624: Successful Logon (PtH and lateral movement checks) ----
            elif event_id == 4624:
                # Pass the Hash detection: type 3 logon executing admin shells or accessing credentials brokers
                if logon_type == 3 and process_name in ("cmd.exe", "powershell.exe", "lsass.exe", "mimikatz.exe"):
                    result = {
                        "score": 0.85,
                        "flags": ["pass_the_hash"],
                        "mitre": [("Credential Access", "T1550.002")],
                        "attack_category": "LATERAL_MOVEMENT",
                    }
                else:
                    ts = event.get("timestamp_dt")
                    if pd.notna(ts):
                        hour = ts.hour
                        dow = ts.dayofweek
                        is_off = (hour < 8 or hour >= 18 or dow >= 5)
                        unusual_type = logon_type in (7, 8, 10)
                        if is_off and unusual_type:
                            result = {
                                "score": 0.50,
                                "flags": ["off_hours_logon"],
                                "mitre": [WINDOWS_MITRE_MAP["off_hours_logon"]],
                                "attack_category": None,
                            }

            # If a result was generated, package it
            if result is not None:
                results.append({
                    "entity": f"{subject_user}@{hostname}",
                    "agent": "behavior",
                    "source": "windows",
                    "event_log_id": event.get("event_log_id", ""),
                    "score": result["score"],
                    "ml_score": 0.0,
                    "rule_score": result["score"],
                    "flags": result["flags"],
                    "mitre": result["mitre"],
                    "source_ip": resolved_ip,
                    "username": subject_user,
                    "hostname": hostname,
                    "timestamp": timestamp,
                    "attack_category": result.get("attack_category", ""),
                })

        self.windows_results = results

        # Print summary
        if results:
            scores = [r["score"] for r in results]
            flag_counts = defaultdict(int)
            for r in results:
                for f in r["flags"]:
                    flag_counts[f] += 1
            print(f"    [BehaviorAgent] Windows analysis complete:")
            print(f"      Threats found : {len(results):,}")
            print(f"      Mean score    : {np.mean(scores):.4f}")
            print(f"      Max score     : {np.max(scores):.4f}")
            print(f"      Threat types  :")
            for flag, count in sorted(flag_counts.items(), key=lambda x: -x[1]):
                print(f"        {flag}: {count}")
        else:
            print("    [BehaviorAgent] No Windows threats detected.")

        return results

    # --------------------------------------------------------------------------
    #  Multi-Source Aggregation
    # --------------------------------------------------------------------------

    def aggregate_by_ip(self, ueba_results, windows_results=None, velocity_results=None):
        """
        Aggregate all results (UEBA + Windows + SWIFT velocity) by source_ip.
        
        Produces one row per IP with:
          - max behavior_score across all sources
          - binary anomaly flag
          - individual indicator flags (both UEBA and Windows derived)
          - total event count
        """
        # Combine all result lists
        all_results = list(ueba_results)
        if windows_results:
            all_results.extend(windows_results)
        if velocity_results:
            all_results.extend(velocity_results)

        ip_data = defaultdict(lambda: {
            "behavior_score": 0.0,
            "is_behavior_anomaly": 0,
            "all_flags": set(),
            "event_count": 0,
            "high_score_count": 0,
            "critical_event": False,
        })

        for r in all_results:
            ip = r.get("source_ip", "")
            if not ip or ip == "LOCAL":
                continue
            data = ip_data[ip]
            data["behavior_score"] = max(data["behavior_score"], r["score"])
            data["event_count"] += 1
            data["all_flags"].update(r["flags"])
            if r["score"] >= 0.70:
                data["high_score_count"] += 1
            if r["score"] >= 0.85:
                data["critical_event"] = True

        rows = []
        for ip, data in ip_data.items():
            flags = data["all_flags"]
            # Require minimum evidence: 2+ events >= 0.70 OR 1 critical event >= 0.85
            is_anomaly = 1 if (data["behavior_score"] >= 0.70 and
                              (data["high_score_count"] >= 2 or data["critical_event"])) else 0
            rows.append({
                "source_ip": ip,
                "behavior_score": round(data["behavior_score"], 4),
                "is_behavior_anomaly": is_anomaly,
                # UEBA indicators
                "ind_off_hours": 1 if ("off_hours" in flags or
                                       "swift_off_hours" in flags or
                                       "weekend_early_morning" in flags) else 0,
                "ind_high_deviation": 1 if ("high_peer_deviation" in flags or
                                            "elevated_peer_deviation" in flags) else 0,
                "ind_large_transfer": 1 if "large_data_transfer" in flags else 0,
                "ind_unauthorized_db": 1 if "unauthorized_pumori" in flags else 0,
                "ind_swift_access": 1 if ("swift_off_hours" in flags or
                                          "new_swift_resource" in flags or
                                          "swift_query_velocity" in flags) else 0,
                # Windows indicators
                "ind_credential_dump": 1 if "credential_dump" in flags else 0,
                "ind_log_cleared": 1 if "audit_log_cleared" in flags else 0,
                "ind_brute_force": 1 if ("brute_force" in flags or
                                         "account_lockout" in flags) else 0,
                "ind_new_service": 1 if ("new_service" in flags or
                                         "new_service_atm" in flags) else 0,
                "ind_priv_escalation": 1 if "priv_escalation" in flags else 0,
                # Metadata
                "behavior_event_count": data["event_count"],
            })

        output_df = pd.DataFrame(rows)
        if not output_df.empty:
            output_df = output_df.sort_values("behavior_score", ascending=False)

        print(f"    [BehaviorAgent] Aggregated to {len(output_df)} unique source IPs")
        n_anomalous = (output_df["is_behavior_anomaly"] == 1).sum() if not output_df.empty else 0
        print(f"    [BehaviorAgent] Anomalous IPs: {n_anomalous}")

        return output_df.reset_index(drop=True)
