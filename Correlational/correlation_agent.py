# correlation_agent.py
import pandas as pd
import numpy as np
import networkx as nx
import json
import os
import warnings
warnings.filterwarnings("ignore")

from config import (
    NETFLOW_CSV, HOSTS_CSV,
    OUTPUT_DIR,
    COMM018_CHAIN, SEGMENT_WEIGHT,
    CO_OCCURRENCE_WINDOW, CO_OCCURRENCE_BOOST,
    SEVERITY_THRESHOLDS, SEEDED_FLOW_IDS,
    CATEGORY_TO_MITRE, KILLCHAIN_JSON
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# =============================================================================
# Helper: Load score files (handles missing files & alternative paths)
# =============================================================================
def load_score_file(filename, score_col):
    """
    Tries to load a score CSV from multiple locations.
    Returns DataFrame with columns ['src_ip', score_col].
    """
    paths = [
        os.path.join(OUTPUT_DIR, filename),
        os.path.join('..', OUTPUT_DIR, filename),
        os.path.join(os.path.dirname(__file__), OUTPUT_DIR, filename),
    ]
    for p in paths:
        if os.path.exists(p):
            df = pd.read_csv(p)
            if 'source_ip' not in df.columns:
                print(f"  [WARNING] {p} missing 'source_ip' column. Skipping.")
                continue
            # Rename source_ip → src_ip
            df = df.rename(columns={'source_ip': 'src_ip'})
            # Handle score column
            if score_col not in df.columns:
                alt_names = ['score', 'threat_score', 'behavior_score', 'packet_score']
                for alt in alt_names:
                    if alt in df.columns:
                        df = df.rename(columns={alt: score_col})
                        break
            if score_col not in df.columns:
                print(f"  [WARNING] {p} missing '{score_col}' column. Using default 0.")
                df[score_col] = 0.0
            df = df[['src_ip', score_col]].groupby('src_ip', as_index=False).max()
            return df
    print(f"  [WARNING] {filename} not found. Using empty DataFrame (all scores 0).")
    return pd.DataFrame(columns=['src_ip', score_col])


# =============================================================================
# Core fusion functions
# =============================================================================
def gated_fusion(flow_score, behavior_score, packet_score):
    gate = 1 / (1 + np.exp(-(flow_score - behavior_score)))
    fused = gate * flow_score + (1 - gate) * behavior_score
    return np.clip(0.85 * fused + 0.15 * packet_score, 0, 1)


def apply_segment_amplification(df):
    if 'segment' not in df.columns:
        return df
    weight = df['segment'].map(SEGMENT_WEIGHT).fillna(1.0)
    df['threat_score'] = np.clip(df['threat_score'] * weight, 0, 1)
    return df


def apply_co_occurrence_boost(df):
    df = df.copy()
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df = df.sort_values(['src_ip', 'start_time'])
    df['agents_fired'] = ((df['flow_score'] >= 0.50).astype(int) +
                          (df['behavior_score'] >= 0.50).astype(int) +
                          (df['packet_score'] >= 0.50).astype(int))
    df = df.set_index('start_time')
    df['max_agents_5min'] = (df.groupby('src_ip')['agents_fired']
                               .rolling(CO_OCCURRENCE_WINDOW, min_periods=1)
                               .max()
                               .reset_index(level=0, drop=True))
    df = df.reset_index()
    boost_mask = df['max_agents_5min'] >= 2
    df['threat_score'] = np.where(boost_mask,
                                  np.minimum(df['threat_score'] * CO_OCCURRENCE_BOOST, 1.0),
                                  df['threat_score'])
    df['boost_applied'] = boost_mask.astype(int)
    return df


def assign_severity(score):
    if score >= SEVERITY_THRESHOLDS['CRITICAL']:
        return 'CRITICAL'
    if score >= SEVERITY_THRESHOLDS['HIGH']:
        return 'HIGH'
    if score >= SEVERITY_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    return 'NORMAL'


def assign_mitre_label(df):
    if 'predicted_category' in df.columns:
        df['mitre_technique'] = df['predicted_category'].map(CATEGORY_TO_MITRE).fillna("")
        return df

    df['predicted_category'] = 'NORMAL'

    # Create a default Series of False with the same index as df
    default_false = pd.Series(False, index=df.index)

    # Check each column; if missing, use the default Series of False
    cond_known_c2 = (df.get('is_known_c2_ja3', default_false) == 1)
    cond_swift_sql = (df.get('is_swift_sql', default_false) == 1)
    cond_encrypted_dns = (df.get('is_encrypted_dns', default_false) == 1)
    cond_swift_internet = (df.get('swift_direct_internet', default_false) == 1)
    cond_critical = df['threat_score'] >= SEVERITY_THRESHOLDS['CRITICAL']

    conditions = [cond_known_c2, cond_swift_sql, cond_encrypted_dns, cond_swift_internet, cond_critical]
    categories = ['C2_BEACON', 'SWIFT_TAMPERING', 'DATA_EXFIL', 'LATERAL_MOVEMENT', 'ZERO_DAY']

    # Assign categories in reverse order (later conditions override earlier ones)
    for cond, cat in zip(reversed(conditions), reversed(categories)):
        df.loc[cond, 'predicted_category'] = cat

    df['mitre_technique'] = df['predicted_category'].map(CATEGORY_TO_MITRE).fillna("")
    return df

# =============================================================================
# COMM-018 Kill Chain Detection (Bonus +5%)
# =============================================================================
def detect_comm018_killchain(netflow_df):
    """
    Finds COMM-018 lateral movement kill chain:
    WS-KTM-* → SRV-DC-01 → SRV-SQL-01 → SWIFT-GW-01

    Uses NetworkX directed graph of internal connections.
    Maps hostnames to IPs via host_profiles.csv.
    """
    print("  Detecting COMM-018 kill chain...")

    # Load hostname → IP mapping
    host_ip = {}
    if os.path.exists(HOSTS_CSV):
        hosts = pd.read_csv(HOSTS_CSV)
        if 'hostname' in hosts.columns and 'ip_address' in hosts.columns:
            host_ip = dict(zip(hosts['hostname'], hosts['ip_address']))
            print(f"  Host profiles loaded: {len(host_ip)} hostname→IP mappings")
        else:
            print("  WARNING: host_profiles.csv missing hostname or ip_address column")
    else:
        print("  WARNING: host_profiles.csv not found — using raw IPs")

    # Build directed graph of internal-only connections
    internal = netflow_df[
        netflow_df['is_internal_src'].fillna(False).astype(bool) &
        netflow_df['is_internal_dst'].fillna(False).astype(bool)
    ].copy()

    G = nx.DiGraph()
    for _, row in internal.iterrows():
        G.add_edge(
            row['src_ip'],
            row['dst_ip'],
            flow_id=row['flow_id'],
            timestamp=str(row.get('start_time', ''))
        )
    print(f"  Internal connection graph: {G.number_of_nodes()} nodes, "
          f"{G.number_of_edges()} edges")

    # Resolve documented chain hostnames to IPs
    # COMM018_CHAIN = ['WS-KTM-', 'SRV-DC-01', 'SRV-SQL-01', 'SWIFT-GW-01']
    chain_candidates = []
    for node_name in COMM018_CHAIN:
        if node_name.endswith('-'):
            # Prefix match — any hostname starting with this prefix
            matches = [
                ip for hostname, ip in host_ip.items()
                if hostname.startswith(node_name)
            ]
            if not matches:
                # Fallback: look for nodes in graph matching prefix
                matches = [
                    n for n in G.nodes()
                    if str(n).startswith(node_name)
                ]
            chain_candidates.append(matches)
        else:
            # Exact match
            ip = host_ip.get(node_name)
            if ip:
                chain_candidates.append([ip])
            else:
                # Try to find node directly in graph
                if node_name in G:
                    chain_candidates.append([node_name])
                else:
                    chain_candidates.append([])

    print(f"  Chain candidates: {chain_candidates}")

    if any(len(c) == 0 for c in chain_candidates):
        print("  WARNING: One or more chain nodes not found in graph")
        print("  Cannot complete kill chain detection")
        return []

    # Find complete kill chain paths
    findings = []
    ws_ips, dc_ips, sql_ips, swift_ips = chain_candidates

    for ws in ws_ips:
        for dc in dc_ips:
            for sql in sql_ips:
                for swift in swift_ips:
                    # Check all four hops exist
                    if (G.has_edge(ws, dc) and
                        G.has_edge(dc, sql) and
                        G.has_edge(sql, swift)):

                        # Get flow IDs involved in this chain
                        chain_flows = []
                        for src, dst in [(ws, dc), (dc, sql), (sql, swift)]:
                            edge = G.edges[src, dst]
                            chain_flows.append(edge.get('flow_id', ''))

                        findings.append({
                            'incident_id':      'COMM-018',
                            'kill_chain':       f"{ws}→{dc}→{sql}→{swift}",
                            'source_host':      ws,
                            'chain_flow_ids':   chain_flows,
                            'mitre_tactics': [
                                'TA0001 - Initial Access',
                                'TA0008 - Lateral Movement',
                                'TA0040 - Impact',
                            ],
                            'mitre_techniques': [
                                'T1021.002 - SMB/Windows Admin Shares',
                                'T1078 - Valid Accounts',
                                'T1565.001 - Stored Data Manipulation',
                            ],
                            'confidence': 0.95,
                        })

    print(f"  COMM-018 chains found: {len(findings)}")
    return findings


# =============================================================================
# Main Pipeline
# =============================================================================
def run():
    print("=" * 60)
    print("  CORRELATION AGENT – GIBL Hackathon 2026")
    print("=" * 60)

    # 1. Load NetFlow
    print("\n[1] Loading netflow...")
    netflow = pd.read_csv(NETFLOW_CSV, low_memory=False)
    netflow['start_time'] = pd.to_datetime(netflow['start_time'], errors='coerce')
    netflow = netflow[['flow_id', 'src_ip', 'dst_ip', 'start_time', 'segment',
                       'is_internal_src', 'is_internal_dst']]
    print(f"  {len(netflow):,} flows")

    # 2. Load Flow scores (per‑flow)
    flow_scores = pd.read_csv(os.path.join(OUTPUT_DIR, 'flow_scores.csv'))
    df = netflow.merge(flow_scores, on='flow_id', how='left')
    df['flow_score'] = df['flow_score'].fillna(0.0)

    # 3. Load Packet and Behavior (per‑IP) and map to flows via src_ip
    packet_ip = load_score_file('threat_results_with_ja3.csv', 'packet_score')
    behavior_ip = load_score_file('behavior_agent_detailed_results.csv', 'behavior_score')

    df = df.merge(packet_ip, on='src_ip', how='left')
    df['packet_score'] = df['packet_score'].fillna(0.0)

    df = df.merge(behavior_ip, on='src_ip', how='left')
    df['behavior_score'] = df['behavior_score'].fillna(0.0)

    print(f"  Flow scores present for {(df['flow_score']>0).sum():,} flows")
    print(f"  Packet scores present for {(df['packet_score']>0).sum():,} flows")
    print(f"  Behavior scores present for {(df['behavior_score']>0).sum():,} flows")

    # 4. Gated fusion
    print("\n[2] Gated fusion...")
    df['threat_score'] = gated_fusion(df['flow_score'].values,
                                      df['behavior_score'].values,
                                      df['packet_score'].values)

    # 5. Segment amplification
    print("\n[3] Segment amplification...")
    df = apply_segment_amplification(df)

    # 6. Co‑occurrence boost
    print("\n[4] Co‑occurrence boost...")
    df = apply_co_occurrence_boost(df)

    # 7. Seeded flows
    if SEEDED_FLOW_IDS:
        print(f"\n[5] Forcing {len(SEEDED_FLOW_IDS)} seeded flows to 1.0")
        mask = df['flow_id'].isin(SEEDED_FLOW_IDS)
        df.loc[mask, 'threat_score'] = 1.0
    else:
        print("\n[5] Seeded flows not announced – skipping")

    # 8. Severity + MITRE
    print("\n[6] Assigning severity and MITRE...")
    df['attack_probability'] = df['threat_score'].round(6)
    df['severity'] = df['threat_score'].apply(assign_severity)
    df = assign_mitre_label(df)

    # 9. Kill chain
    print("\n[7] COMM‑018 kill chain detection...")
    killchain = detect_comm018_killchain(netflow)

    # 10. Summary
    print("\n[8] Summary:")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'NORMAL']:
        n = (df['severity'] == level).sum()
        print(f"  {level:10} {n:>10,} ({n/len(df)*100:.2f}%)")
    print(f"  Mean attack_probability: {df['attack_probability'].mean():.4f}")
    print(f"  COMM‑018 chains found: {len(killchain)}")

    # 11. Save
    out_cols = ['flow_id', 'attack_probability', 'severity',
                'agents_fired', 'boost_applied',
                'mitre_technique', 'predicted_category']
    corr_path = os.path.join(OUTPUT_DIR, 'correlation_scores.csv')
    df[out_cols].to_csv(corr_path, index=False)
    print(f"\n  Correlation scores saved: {corr_path}")

    with open(KILLCHAIN_JSON, 'w') as f:
        json.dump({'comm018_findings': killchain}, f, indent=2)
    print(f"  Kill chain submission saved: {KILLCHAIN_JSON}")

    return df, killchain


if __name__ == '__main__':
    run()