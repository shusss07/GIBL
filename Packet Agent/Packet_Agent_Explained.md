# Packet Agent — How It Works

This notebook is a **network/endpoint threat-hunting agent** called "GIBL Threat Agent." It ingests two different log sources (Windows security events and Zeek network connection logs), builds per-IP behavioral fingerprints, and uses an **unsupervised anomaly detection model (Isolation Forest)** to rank source IPs by how "weird" their behavior looks compared to everyone else — without needing labeled attack data. It then layers on some rule-based, human-readable indicators (including a JA3 TLS-fingerprint check for C2 malware) to help an analyst understand *why* something was flagged.

There is no labeled "this IP is malicious" column anywhere. The whole design is built around that constraint: statistical outlier detection + explainability, not classification.

---

## 1. Big-picture pipeline

```
windows_event_logs.csv ─┐
                         ├─► per-source-IP feature engineering ─┐
zeek_conn_logs.csv ──────┘                                      ├─► merge on source_ip ─► scale ─► Isolation Forest ─► threat_score
                                                                  │
                                                            JA3 hash analysis (Zeek only)
                                                                  │
                                                            informational indicators (not model inputs)
                                                                  │
                                                            ranked CSV outputs
```

Two output files are produced:
- `threat_results.csv` — the core model output (every IP, sorted by threat score)
- `threat_results_with_ja3.csv` — the same table enriched with JA3/C2 signal columns

---

## 2. Loading the data (Cell 4)

Two CSVs are read with pandas:
- `windows_event_logs.csv` → host-level security events (logons, process creation, service installs, etc.)
- `zeek_conn_logs.csv` → network flow/connection metadata captured by Zeek (an open-source network monitor)

Both are printed with row counts as a sanity check before any transformation happens.

---

## 3. Windows feature engineering (Cells 5–9)

**Goal:** turn a raw event log (one row per event) into one row per `source_ip` describing that IP's overall behavior.

### Step 1 — Clean up
- `timestamp` is parsed into a real datetime.
- Missing `source_ip` values are filled with `"LOCAL"` (events with no IP, e.g. local console activity, still need a bucket instead of being silently dropped).

### Step 2 — Behavioral flags (Cell 6)
Specific Windows Event IDs are turned into binary flags per row:
| Column | Meaning |
|---|---|
| `is_failed_logon` | Event ID 4625 — failed logon attempt |
| `is_process_create` | Event ID 4688 — new process started |
| `is_privileged_logon` | Event ID 4672 — logon with admin/special privileges |
| `is_service_install` | Event ID 7045 — a new Windows service was installed (classic persistence technique) |
| `is_rdp_logon` | Logon type 10 — Remote Desktop |
| `is_network_logon` | Logon type 3 — network logon (e.g. SMB, lateral movement indicator) |

**Reasoning:** these specific event IDs/logon types are the standard Windows security-monitoring vocabulary for brute force (4625), execution (4688), privilege use (4672), persistence (7045), and remote access (RDP/network logons) — the core MITRE ATT&CK-adjacent signals analysts look for.

### Step 3 — Data-driven "off-hours" detection (Cell 7)
Instead of hardcoding "9-to-5 is normal," the notebook computes the busiest hours **from the data itself**:
1. Count events per hour of day.
2. Take the hours whose count is ≥ the median hourly count → call these "busy hours."
3. Anything outside busy hours is flagged `is_off_hours`.

**Reasoning:** a hardcoded business-hours assumption (e.g., 8am–6pm) breaks for 24/7 operations, different time zones, or shift-based environments. Deriving "normal activity hours" from the dataset's own distribution makes the off-hours signal adapt to whatever environment the logs came from.

### Step 4 — Aggregate to one row per IP (Cell 8)
`groupby("source_ip")` produces per-IP counts:
- total events, unique hostnames touched, unique usernames used
- sums of each behavioral flag (failed logons, process creations, privileged logons, service installs, RDP logons, network logons, off-hours events)

**Reasoning for `win_unique_hosts` / `win_unique_users`:** an IP touching many different hosts or authenticating as many different users is a classic lateral-movement / credential-stuffing signature, even if no individual event looks bad.

### Step 5 — Ratio features (Cell 9)
Raw counts are also converted to **ratios of total activity**:
```
win_fail_ratio      = failed_logons / total_events
win_priv_ratio      = privileged_logons / total_events
win_process_ratio   = process_creations / total_events
win_off_hours_ratio = off_hours_events / total_events
```
(`n` is clipped to a minimum of 1 to avoid divide-by-zero.)

**Reasoning:** this is one of the more important design choices in the notebook. Raw counts are biased by volume — a busy domain controller might generate 500 failed logons out of 50,000 events (1% fail rate, totally normal), while a quiet workstation with 5 events, all failures, is far more suspicious (100% fail rate) despite having a smaller raw number. Ratios normalize for how "busy" an IP naturally is, so the model compares *behavioral proportions*, not just volume.

---

## 4. Zeek feature engineering (Cells 10–11)

Same philosophy, applied to network connection logs.

### Row-level derived fields
| Column | Meaning |
|---|---|
| `is_off_hours` | Reuses the *same* `busy_hours` set computed from the Windows data, applied to Zeek timestamps |
| `is_failed_conn` | Connection state is `S0` (no reply) or `REJ` (rejected) — a failed/rejected TCP connection, common in scanning/probing |
| `is_encrypted` | Service is `ssl` or `tls` |
| `bytes_ratio` | `orig_bytes / resp_bytes` (clipped denominator) — how much the source sent vs. received |

**Reasoning for reusing `busy_hours` across both logs:** it keeps the "normal activity window" consistent for the whole environment rather than computing two different, possibly conflicting definitions of "off-hours."

**Reasoning for `bytes_ratio`:** a source sending far more than it receives (high ratio) can indicate data exfiltration; a source receiving far more than it sends can indicate a download/C2 payload pull. Either extreme is informative.

### Aggregation to one row per IP
`groupby("id_orig_h")` (the originating IP) produces, per IP:
- `zeek_total_conns`, `zeek_unique_dst_ips`, `zeek_unique_dst_ports`
- `zeek_failed_conns`, `zeek_encrypted_conns`, `zeek_off_hours_conns`
- `zeek_mean_duration`, `zeek_mean_orig_bytes`, `zeek_mean_resp_bytes`, `zeek_total_orig_bytes`, `zeek_mean_bytes_ratio`, `zeek_mean_orig_pkts`

The column is renamed `id_orig_h → source_ip` so it can later be merged with the Windows table on a common key.

### Zeek ratio/derived features
```
zeek_fail_ratio      = failed_conns / total_conns
zeek_encrypted_ratio = encrypted_conns / total_conns
zeek_off_hours_ratio = off_hours_conns / total_conns
zeek_dst_diversity   = unique_dst_ports / unique_dst_ips
```

**Reasoning for `zeek_dst_diversity`:** an IP hitting many different ports on relatively few destination IPs (high ratio) looks like **port scanning**; an IP hitting many different IPs each on the same port looks more like normal client traffic (e.g., many users hitting port 443). This ratio captures that shape difference in a single number.

---

## 5. Merging the two views of the same IP (Cell 12)

```python
combined = pd.merge(win_feat, zeek_feat, on="source_ip", how="outer").fillna(0)
```

An **outer join** is used deliberately: an IP might only show up in Windows logs (e.g., pure local activity) or only in Zeek logs (e.g., a pure network scanner with no Windows-authenticated activity). Using `outer` + `fillna(0)` keeps every IP in the analysis instead of silently dropping IPs that don't appear in both sources — an inner join would blind the model to IPs with network activity but no host telemetry (or vice versa), which is exactly the kind of "network-only" or "host-only" attacker you don't want to miss.

---

## 6. Scaling + Isolation Forest (Cell 13)

### Feature set
28 numeric columns are fed to the model — 13 Windows behavioral/ratio features and 15 Zeek behavioral/ratio features (listed explicitly in `FEATURE_COLS`). This is entirely counts and ratios; no raw IP addresses, timestamps, or categorical strings go into the model.

### Scaling
```python
scaler = StandardScaler()
X = scaler.fit_transform(X_raw)
```
**Reasoning:** the raw features live on very different scales (e.g., `zeek_total_orig_bytes` can be in the millions while `win_fail_ratio` is between 0 and 1). Isolation Forest itself doesn't strictly require scaling the way distance-based models do, but standardizing still makes the split points more balanced across features of wildly different magnitude and is standard practice before feeding a mixed-scale feature matrix into most sklearn estimators.

### Why Isolation Forest specifically
- It's **unsupervised** — there's no labeled "malicious/benign" column in this data, so a supervised classifier isn't an option.
- It works by randomly partitioning the feature space; anomalies are points that get **isolated in fewer random splits** than normal points (outliers sit in sparse regions, so it takes less work to separate them). This scales well to the ~28-dimensional feature space here without assuming any particular data distribution (unlike, say, a Gaussian-based method).
- `contamination=0.05` tells the model to expect roughly 5% of IPs to be anomalous — a tunable assumption rather than a hard rule, called out explicitly as adjustable in the config cell.
- `n_estimators=200` uses 200 trees for a stable ensemble score.
- `random_state=42` makes results reproducible.
- `n_jobs=-1` parallelizes across all CPU cores.

### Model outputs
- `decision_function(X)` → a raw anomaly score where **more negative = more anomalous**.
- `predict(X)` → hard label, `-1` for anomaly, `1` for normal, based on the contamination threshold.

---

## 7. Turning raw scores into a 0–1 threat score (Cell 14)

```python
threat_score = 1 - (raw_scores - score_min) / (score_max - score_min)
```
This is a **min-max normalization**, then inverted (`1 -`) so that the convention is intuitive: **1.0 = most anomalous/highest threat, 0.0 = most normal**. Without the inversion, the most suspicious IPs would confusingly have the *lowest* number, since Isolation Forest's native convention is "more negative = more anomalous."

`is_anomaly` is just the `-1`/`1` prediction converted to `1`/`0` for readability.

---

## 8. Informational indicators — explainability layer (Cell 15)

This is a deliberate second layer, separate from the model:

```python
fail_thresh   = combined["win_fail_ratio"].quantile(0.90)
upload_thresh = combined["zeek_mean_bytes_ratio"].quantile(0.90)
port_thresh   = combined["zeek_unique_dst_ports"].quantile(0.90)

ind_high_fail_ratio   = win_fail_ratio > fail_thresh        # top 10% by failed-logon ratio
ind_high_upload_ratio = zeek_mean_bytes_ratio > upload_thresh # top 10% by upload-heavy ratio
ind_high_port_spread  = zeek_unique_dst_ports > port_thresh   # top 10% by port diversity
```

**Reasoning:** Isolation Forest gives you a *score*, not a *reason*. These three flags — each just "is this IP in the top 10% of the dataset for this one specific metric?" — are attached to the results purely for a human analyst to read, e.g. "this IP scored high, and here's a hint why: it has an unusually high failed-logon ratio." The code explicitly notes these do **not** feed back into the model — they're computed after the fact and never touch `FEATURE_COLS` or the fitted model, so they can't bias the anomaly detection itself. This separation of "detection" from "explanation" is good practice: it avoids circular logic where an explanatory rule silently becomes part of the score it's supposed to be explaining.

---

## 9. Results printing and export (Cells 16–17)

- Prints total IP count and how many were flagged as anomalies (and what % that is).
- Selects the top `TOP_N` (20) anomalous IPs sorted by `threat_score` descending, and pretty-prints a table with the threat score plus the three indicator flags and two raw counts (failed logons, total Zeek connections) for quick eyeballing.
- Saves the **entire** `combined` table (all IPs, not just the top 20), sorted by threat score, to `threat_results.csv`, so nothing is thrown away — the console output is just a preview.

---

## 10. JA3 hash analysis — C2 beacon detection (Cells 18–21)

This is a second, independent detection technique layered on top, focused specifically on **command-and-control (C2) malware beacons** using **JA3** — a fingerprinting technique that hashes the parameters of a TLS "Client Hello" message (cipher suites, extensions, elliptic curves, etc.) to identify what TLS client library/config is being used to make a connection. Malware families often have distinctive, unusual TLS stacks, making JA3 a well-known way to spot C2 traffic even when it's encrypted.

### Design notes explicitly called out in the notebook
The notebook adapts a pre-existing JA3 analysis snippet to this specific dataset and documents two adjustments:
1. The original approach expected a `flow_label` ground-truth column that doesn't exist in `zeek_conn_logs.csv`. Instead, the notebook builds its "normal" baseline from rows where `is_anomaly == False` (the Isolation Forest's own verdict), falling back to using all rows with a hash if that column isn't present.
2. About 8% of rows have no JA3 hash at all (non-TLS traffic — UDP, ICMP, etc.). These rows are deliberately excluded from both the baseline calculation and the "rare/never-seen" flags, because a missing hash is not evidence of anything suspicious — flagging it would just mislabel a chunk of ordinary non-TLS traffic.

### Step 1 — Build a frequency baseline from "normal" traffic (Cell 18)
```python
normal_ja3 = zeek.loc[has_hash & (zeek["is_anomaly"] == False), "ja3_hash"]
ja3_counts = normal_ja3.value_counts(normalize=True)
```
This gives, for every JA3 hash seen in confirmed-normal traffic, what fraction of normal traffic it represents.

### Step 2 — Score every flow against that baseline (Cell 19)
- `ja3_frequency_in_normal`: how common this flow's hash is in normal traffic (NaN if never seen there).
- `ja3_log_frequency`: a log-transform (`log1p(freq * 10000)`) because hash frequency is extremely skewed — common hashes can be ~1000x more frequent than rare ones, and a log scale keeps that from swamping other features/visualizations.
- `ja3_never_seen_in_normal`: 1 if the flow has a hash but that hash **never** appeared in the normal baseline at all.
- `ja3_is_rare`: 1 if the hash appears in normal traffic, but in less than 0.01% of it.
- `ja3_matches_known_c2`: 1 if the hash exactly matches a documented C2 IOC (`c7d1e3f2a4b6c8d0`, a placeholder for a real threat-intel indicator, noted as appearing in 89% of C2 beacons in whatever source this IOC came from).

**Reasoning for keeping the known-C2 check separate from the rarity score:** JA3 fingerprints the *TLS client library/configuration*, not the specific application. A hash can be common overall (because it's shared by many benign apps using the same TLS stack, e.g. a popular HTTP library) while *also* being the exact hash used by known C2 malware using that same library. Rarity-based logic alone would never flag that hash (it's not rare — it's common), but a direct string match against the known-bad IOC catches it regardless of how common it is elsewhere. This is why both checks exist independently rather than being folded into one "suspicion score."

### Step 3 — Aggregate JA3 signal per source IP (Cell 20)
Same `groupby("id_orig_h")` pattern as the earlier Zeek feature block, producing per-IP sums of never-seen/rare/known-C2 connection counts plus the minimum observed frequency. This is merged onto the existing `combined` table.

Critically: **these columns are added after the model has already been fit.** They do not go into `FEATURE_COLS`, so they cannot change `threat_score`, `is_anomaly`, or the earlier Top-20 table — they're purely additive, informational columns, following the same "detection vs. explanation" separation used for the quantile-based indicators in Section 8.

### Step 4 — Report + save (Cell 21)
Prints the IPs with the strongest JA3 C2/rarity signal (sorted by known-C2 connection count, then rarity count), and saves the full, JA3-enriched table to a **separate** file, `threat_results_with_ja3.csv`, explicitly leaving the original `threat_results.csv` untouched.

---

## 11. Summary of the reasoning threads running through the whole notebook

1. **No labels → unsupervised anomaly detection.** Isolation Forest is chosen because it doesn't need a "malicious" ground truth, just a sense of what's statistically unusual.
2. **Normalize for volume everywhere.** Ratios (fail ratio, priv ratio, off-hours ratio, dst diversity, bytes ratio) repeatedly appear so busy vs. quiet IPs are compared fairly rather than just by raw event counts.
3. **Derive "normal" from the data, not hardcoded assumptions.** Both "busy hours" and the JA3 "normal traffic" baseline are computed from the dataset itself, not fixed rules, so the same notebook adapts to different environments.
4. **Keep detection and explanation separate.** The Isolation Forest model only ever sees `FEATURE_COLS`. Everything added afterward — the quantile-based indicators (Section 8) and the JA3 columns (Section 10) — is explicitly documented as informational-only and provably can't leak into or bias the model's score, which avoids circular reasoning (i.e., a hand-crafted rule quietly becoming the thing that "explains" itself).
5. **Don't throw data away on the merges.** Outer join on `source_ip` and inclusion of all IPs (not just top-N) in the saved CSV both reflect a "don't silently drop what you didn't expect" philosophy — useful for security data, where the least-expected IP is often the interesting one.
6. **Two independent detection angles.** Host-behavior anomaly (Isolation Forest, primarily Windows+Zeek behavioral features) and network-crypto-fingerprint anomaly (JA3 rarity/IOC matching) are complementary — the first catches "this IP is behaving strangely across many dimensions," the second specifically targets "this IP's encrypted traffic has the fingerprint of known C2 malware," which the first approach could miss entirely since it doesn't look inside TLS metadata at all.

---

## 12. Known limitations / things worth flagging to a user of this notebook

- `CONTAMINATION = 0.05` is a guess (5% of IPs assumed anomalous); if the real anomaly rate in a given environment is very different, the flagged count and threshold will be off — the config comment itself says "tune as needed."
- The `KNOWN_C2_JA3` hash is a single hardcoded IOC — this only catches that one specific known-bad fingerprint, not JA3-based C2 detection in general (real deployments would pull from a threat-intel feed).
- The "normal" JA3 baseline is built from `is_anomaly == False`, i.e. from the *model's own* verdict — if the Isolation Forest already mis-scored some malicious IPs as normal, those flows would incorrectly count toward the "normal" baseline, potentially diluting the rarity signal for similar hashes.
- All feature engineering assumes the specific column names/schemas of these two log formats (`windows_event_logs.csv`, `zeek_conn_logs.csv`); it isn't a generic parser.
