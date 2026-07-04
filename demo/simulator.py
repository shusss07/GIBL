"""
GIBL IDS Live Demo — Traffic Simulator
=======================================
Simulates realistic benign banking traffic AND three distinct cyberattack
patterns drawn directly from our Track D dataset:

  Attack 1 — Data Exfiltration (External → Core Banking)
  Attack 2 — SWIFT SQL Injection Probe (Internal lateral movement)
  Attack 3 — C2 Beacon with Known Malicious JA3 Hash (Encrypted DNS)
"""

import urllib.request
import urllib.error
import time
import random
import threading
import sys

TARGET_URL = "http://localhost:8080"
RUNNING = True

# ── Benign IPs (internal employees) ─────────────────────────────
BENIGN_IPS = [f"192.168.1.{i}" for i in range(100, 115)]

# ── Attack Profiles ─────────────────────────────────────────────

ATTACK_1 = {
    "name":  "Data Exfiltration",
    "ip":    "45.142.212.65",
    "desc":  "External IP exfiltrating massive data from Core Banking",
}

ATTACK_2 = {
    "name":  "SWIFT SQL Probe",
    "ip":    "10.30.1.200",
    "desc":  "Compromised internal host scanning SWIFT SQL Server (port 1433)",
}

ATTACK_3 = {
    "name":  "C2 Beacon (JA3 + Encrypted DNS)",
    "ip":    "10.10.3.59",
    "desc":  "Infected workstation beaconing to C2 via DNS-over-TLS with known malicious JA3",
}

# ── Helpers ──────────────────────────────────────────────────────

def send(ip, headers):
    """Fire a single request with simulation headers."""
    path = random.choice(["/", "/login", "/transfer", "/api/data"])
    req = urllib.request.Request(TARGET_URL + path, method="GET")
    req.add_header("X-Forwarded-For", ip)
    for k, v in headers.items():
        req.add_header(k, str(v))
    try:
        urllib.request.urlopen(req, timeout=2)
    except urllib.error.HTTPError:
        pass   # 403 = blocked, expected
    except Exception:
        pass

# ── Workers ──────────────────────────────────────────────────────

def benign_worker():
    """Normal banking employees browsing internal systems."""
    while RUNNING:
        ip = random.choice(BENIGN_IPS)
        pkts = random.randint(5, 15)
        headers = {
            "X-Simulate-Packets": pkts,
            "X-Simulate-Bytes":   pkts * random.randint(1430, 1470),
            "X-Simulate-Segment": random.choice(["CORE_BANKING", "WORKSTATION"]),
            "X-Simulate-Port":    random.choice([80, 443, 8080]),
        }
        send(ip, headers)
        time.sleep(random.uniform(0.2, 0.6))


def attack_exfiltration():
    """Attack 1 — Massive data upload from external IP.
    Signature: tiny packets, huge byte volume, external src → internal dst."""
    ip = ATTACK_1["ip"]
    while RUNNING:
        pkts  = random.randint(800, 50000)
        bpp   = random.randint(2, 100)          # very small bytes-per-packet
        headers = {
            "X-Simulate-Packets": pkts,
            "X-Simulate-Bytes":   pkts * bpp,
            "X-Simulate-Segment": "CORE_BANKING",
            "X-Simulate-Port":    random.choice([8080, 443, 3389]),
        }
        send(ip, headers)
        time.sleep(random.uniform(0.05, 0.15))


def attack_swift_sql():
    """Attack 2 — Rapid-fire SQL queries against SWIFT segment.
    Signature: port 1433, SWIFT segment, small packets, high frequency."""
    ip = ATTACK_2["ip"]
    while RUNNING:
        pkts = random.randint(50, 500)
        headers = {
            "X-Simulate-Packets": pkts,
            "X-Simulate-Bytes":   pkts * random.randint(10, 200),
            "X-Simulate-Segment": "SWIFT",
            "X-Simulate-Port":    1433,
        }
        send(ip, headers)
        time.sleep(random.uniform(0.01, 0.05))   # very high frequency


def attack_c2_beacon():
    """Attack 3 — C2 Beacon over Encrypted DNS with known malicious JA3.
    Signature: known C2 JA3 hash, DNS-over-TLS port 853, Saturday 3-5 AM window."""
    ip = ATTACK_3["ip"]
    while RUNNING:
        pkts = random.randint(3, 30)
        headers = {
            "X-Simulate-Packets": pkts,
            "X-Simulate-Bytes":   pkts * random.randint(50, 400),
            "X-Simulate-Segment": "WORKSTATION",
            "X-Simulate-Port":    853,
            "X-Simulate-JA3":     "c7d1e3f2a4b6c8d0",            # known C2 hash
            "X-Simulate-Time":    f"2026-07-04 0{random.randint(3,4)}:{random.randint(0,59):02d}:00",
        }
        send(ip, headers)
        time.sleep(random.uniform(0.3, 1.0))    # slow beaconing


# ── Main ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║           GIBL TRAFFIC SIMULATOR — LIVE DEMO            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    print("[SIM] Starting benign banking traffic (15 employees)...")
    for _ in range(5):
        threading.Thread(target=benign_worker, daemon=True).start()

    print("[SIM] Benign traffic flowing.  Waiting 5 s before attacks...\n")
    time.sleep(5)

    print("═" * 58)
    print("  ⚠️  CYBERATTACKS LAUNCHING")
    print("═" * 58)
    print()
    print(f"  1. {ATTACK_1['name']:30s}  {ATTACK_1['ip']}")
    print(f"     └─ {ATTACK_1['desc']}")
    print(f"  2. {ATTACK_2['name']:30s}  {ATTACK_2['ip']}")
    print(f"     └─ {ATTACK_2['desc']}")
    print(f"  3. {ATTACK_3['name']:30s}  {ATTACK_3['ip']}")
    print(f"     └─ {ATTACK_3['desc']}")
    print()

    threading.Thread(target=attack_exfiltration, daemon=True).start()
    threading.Thread(target=attack_swift_sql,    daemon=True).start()
    threading.Thread(target=attack_c2_beacon,    daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        RUNNING = False
        print("\n[SIM] Shutting down.")
        sys.exit(0)
