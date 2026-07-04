#!/usr/bin/env python3
"""
Master pipeline runner — runs all 5 agents in sequence.
Usage: python3 run_pipeline.py
"""
import os
import sys
import time
import subprocess
import shutil

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(PROJECT_DIR, "outputs")
TRACK_D = "/Users/pratik/Downloads/Track D"

os.makedirs(OUTPUTS_DIR, exist_ok=True)

def banner(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def run_step(label, cmd, cwd=None):
    banner(label)
    t0 = time.time()
    result = subprocess.run(cmd, cwd=cwd or PROJECT_DIR, capture_output=False)
    elapsed = time.time() - t0
    if result.returncode != 0:
        print(f"  *** {label} FAILED (exit code {result.returncode}) ***")
        return False
    print(f"  [{label}] completed in {elapsed:.1f}s")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Packet Agent
# ─────────────────────────────────────────────────────────────────────────────
ok = run_step(
    "STEP 1/5 — Packet Agent",
    [sys.executable, os.path.join(PROJECT_DIR, "Packet Agent", "packet_agent_runner.py")],
    cwd=os.path.join(PROJECT_DIR, "Packet Agent"),
)
if not ok:
    print("Packet Agent failed. Continuing with empty packet scores...")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Flow Agent
# ─────────────────────────────────────────────────────────────────────────────
ok = run_step(
    "STEP 2/5 — Flow Agent",
    [sys.executable, os.path.join(PROJECT_DIR, "Flow", "run_flow_agent.py")],
    cwd=os.path.join(PROJECT_DIR, "Flow"),
)
if not ok:
    print("Flow Agent failed. Pipeline cannot continue without flow scores.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Behavior Agent
# ─────────────────────────────────────────────────────────────────────────────
# The behavior agent already has a pre-computed output. Copy it to outputs/.
behavior_src = os.path.join(PROJECT_DIR, "Behaviour", "behavior_agent_detailed_results.csv")
behavior_dst = os.path.join(OUTPUTS_DIR, "behavior_agent_detailed_results.csv")
if os.path.exists(behavior_src):
    banner("STEP 3/5 — Behavior Agent (using pre-computed output)")
    shutil.copy2(behavior_src, behavior_dst)
    print(f"  Copied {behavior_src} → {behavior_dst}")
else:
    # Try running it
    ok = run_step(
        "STEP 3/5 — Behavior Agent",
        [sys.executable, os.path.join(PROJECT_DIR, "Behaviour", "run_behavior_agent.py"),
         "--ueba", os.path.join(TRACK_D, "ueba_user_behavior.csv"),
         "--windows", os.path.join(TRACK_D, "windows_event_logs.csv"),
         "--hosts", os.path.join(TRACK_D, "host_profiles.csv")],
    )
    if not ok:
        print("Behavior Agent failed. Continuing with empty behavior scores...")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Correlation Agent
# ─────────────────────────────────────────────────────────────────────────────
ok = run_step(
    "STEP 4/5 — Correlation Agent",
    [sys.executable, os.path.join(PROJECT_DIR, "Correlational", "correlation_agent.py")],
)
if not ok:
    print("Correlation Agent failed. Cannot continue.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Response Agent
# ─────────────────────────────────────────────────────────────────────────────
ok = run_step(
    "STEP 5/5 — Response Agent",
    [sys.executable, os.path.join(PROJECT_DIR, "response_agent.py")],
)
if not ok:
    print("Response Agent failed.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────────────────────
banner("PIPELINE COMPLETE")
print("  Final outputs:")
for f in os.listdir(OUTPUTS_DIR):
    fpath = os.path.join(OUTPUTS_DIR, f)
    if os.path.isfile(fpath):
        size_mb = os.path.getsize(fpath) / (1024 * 1024)
        print(f"    {f:45s} {size_mb:8.1f} MB")
