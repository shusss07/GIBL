# config.py
# Everything explicitly stated in the GIBL data description.
# These are facts, not assumptions. Hardcoding is correct here.

# Pattern 4: Documented C2 JA3 hash — 89% precision
KNOWN_C2_JA3_HASH = 'c7d1e3f2a4b6c8d0'

# Pattern 2: SWIFT SQL Server port
SWIFT_SQL_PORT = 1433

# Pattern 3: Encrypted DNS port
ENCRYPTED_DNS_PORT = 853

# Pattern 7: COMM-018 kill chain nodes
COMM018_CHAIN = ['WS-KTM-', 'SRV-DC-01', 'SRV-SQL-01', 'SWIFT-GW-01']

# Pattern 1: C2 beacon time window (67% documented hit rate)
C2_BEACON_DAY  = 5      # Saturday
C2_BEACON_HOUR_START = 3
C2_BEACON_HOUR_END   = 5

# Network segments from data description
SEGMENTS = ['SWIFT', 'CORE_BANKING', 'ATM', 'WORKSTATION', 'DMZ']

# Segment risk — SWIFT and CORE_BANKING are highest value targets
SEGMENT_RISK = {
    'SWIFT':        1.0,
    'CORE_BANKING': 0.8,
    'ATM':          0.6,
    'DMZ':          0.4,
    'WORKSTATION':  0.2,
}

# High-value destination ports with their risk scores
# Only the ones explicitly mentioned in the data description
PORT_RISK = {
    1433: 0.8,   # SQL Server — Pattern 2
    853:  0.9,   # DNS over TLS — Pattern 3
    3389: 0.7,   # RDP — lateral movement
    445:  0.7,   # SMB — ransomware
    22:   0.3,   # SSH — legitimate but targeted
}


NETFLOW_CSV = "netflow_records.csv"
TRAIN_LABELS_CSV = "ids_labels_train.csv"
HOSTS_CSV = "host_profiles.csv"
WINDOWS_LOG = "windows_event_logs.csv"
ZEEK_LOG = "zeek_conn_logs.csv"  
OUTPUT_DIR = "output"

# === Correlation Agent Constants ===

# Segment amplification weights (SWIFT and ATM are most critical)
SEGMENT_WEIGHT = {
    'SWIFT':         1.25,
    'ATM':           1.20,
    'CORE_BANKING':  1.10,
    'DMZ':           1.00,
    'WORKSTATION':   0.90,
    'INTERNAL':      0.95,    # fallback for internal segments
}

# Severity thresholds (attack_probability)
SEVERITY_THRESHOLDS = {
    'MEDIUM':   0.50,
    'HIGH':     0.70,
    'CRITICAL': 0.85,
}

# Co-occurrence boost parameters (5-minute window, 1.30x boost)
CO_OCCURRENCE_WINDOW = '5min'
CO_OCCURRENCE_BOOST = 1.30

# Kill chain hostname patterns for COMM-018 (bonus)
COMM018_CHAIN = ['WS-KTM-', 'SRV-DC-01', 'SRV-SQL-01', 'SWIFT-GW-01']

# Directory and file names
OUTPUT_DIR = "output"
KILLCHAIN_JSON = "killchain_submission.json"

# Seeded flow IDs (if announced by organizers; otherwise empty)
SEEDED_FLOW_IDS = []   # e.g., ['NF-20260531-A9F3C1AB', ...]

# Mapping from attack category → MITRE ATT&CK technique ID
CATEGORY_TO_MITRE = {
    'C2_BEACON':         'T1071.001',
    'LATERAL_MOVEMENT':  'T1021.002',
    'DATA_EXFIL':        'T1041',
    'PORT_SCAN':         'T1046',
    'BRUTE_FORCE':       'T1110',
    'RANSOMWARE_STAGING':'T1486',
    'INSIDER_THREAT':    'T1078',
    'SWIFT_TAMPERING':   'T1005',
    'ATM_JACKPOTTING':   'T1543.003',
    'ZERO_DAY':          'T0000',   # placeholder for unknown technique
    'NORMAL':            '',
}

# If you already have these paths defined, keep them; otherwise add:
NETFLOW_CSV = "netflow_records.csv"
HOSTS_CSV = "host_profiles.csv"
TICKETS_CSV = "incident_tickets.csv"

# Score file paths (relative to OUTPUT_DIR)
FLOW_SCORES_CSV = "output/flow_scores.csv"
PACKET_SCORES_CSV = "output/packet_scores_by_ip.csv"
BEHAVIOR_SCORES_CSV = "output/behavior_scores_by_ip.csv"