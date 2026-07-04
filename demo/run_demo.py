"""
GIBL IDS Live Demo — Orchestrator & Interactive Console
=========================================================
Launches the Target Server and IDS Engine as subprocesses,
then provides an interactive CLI to manually fire specific 
network traffic profiles to test the IDS.
"""

import subprocess
import time
import sys
import os
import threading
import urllib.request
import urllib.error
import random

COLORS = {
    "SERVER":    "\033[94m",   # blue
    "IDS":       "\033[92m",   # green
    "CONSOLE":   "\033[95m",   # magenta
    "RESET":     "\033[0m",
}

TARGET_URL = "http://localhost:8080"

def stream_output(process, prefix, color):
    """Read lines from a subprocess and print them color-coded."""
    reset = COLORS["RESET"]
    for line in iter(process.stdout.readline, ''):
        if line:
            # We use carriage return magic to print over the input prompt cleanly if possible, 
            # though standard print is fine for a demo.
            print(f"\r{color}[{prefix}] {line.rstrip()}{reset}")

def send_traffic(ip, headers):
    path = random.choice(["/", "/login", "/transfer", "/api/data"])
    req = urllib.request.Request(TARGET_URL + path, method="GET")
    req.add_header("X-Forwarded-For", ip)
    for k, v in headers.items():
        req.add_header(k, str(v))
    try:
        urllib.request.urlopen(req, timeout=2)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"{COLORS['CONSOLE']}[CONSOLE] 🚫 Connection REJECTED by Firewall (IP {ip} is BLOCKED)!{COLORS['RESET']}")
    except Exception:
        pass

# ── Payload Generators ───────────────────────────────────────────

def get_random_external_ip():
    # Exclude 10.x.x.x, 172.16.x.x, 192.168.x.x
    return f"{random.choice([45, 82, 185, 203])}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(1, 254)}"

def get_random_internal_ip():
    return f"10.{random.randint(10, 50)}.{random.randint(1, 5)}.{random.randint(20, 250)}"

def trigger_benign():
    ip = f"192.168.1.{random.randint(100, 115)}"
    pkts = random.randint(5, 15)
    headers = {
        "X-Simulate-Packets": pkts,
        "X-Simulate-Bytes":   pkts * random.randint(1430, 1470),
        "X-Simulate-Segment": random.choice(["CORE_BANKING", "WORKSTATION"]),
        "X-Simulate-Port":    random.choice([80, 443, 8080]),
    }
    print(f"{COLORS['CONSOLE']}[CONSOLE] 🟢 Firing BENIGN traffic from {ip}...{COLORS['RESET']}")
    send_traffic(ip, headers)

def trigger_exfil():
    ip = get_random_external_ip()
    pkts  = random.randint(1000, 75000)
    bpp   = random.randint(2, 60) # tiny packets
    headers = {
        "X-Simulate-Packets": pkts,
        "X-Simulate-Bytes":   pkts * bpp,
        "X-Simulate-Segment": random.choice(["CORE_BANKING", "DMZ", "WORKSTATION"]),
        "X-Simulate-Port":    random.choice([8080, 443, 3389, 22, 21]),
        "X-Simulate-Packet-Score": round(random.uniform(0.1, 0.3), 2),     # Packets look somewhat normal, just lots of them
        "X-Simulate-Behavior-Score": round(random.uniform(0.2, 0.4), 2),   # Behavior is mildly suspicious
    }
    print(f"{COLORS['CONSOLE']}[CONSOLE] 🔴 Firing DATA EXFILTRATION attack from {ip}...{COLORS['RESET']}")
    send_traffic(ip, headers)

def trigger_swift():
    ip = get_random_internal_ip()
    pkts = random.randint(50, 1500)
    headers = {
        "X-Simulate-Packets": pkts,
        "X-Simulate-Bytes":   pkts * random.randint(10, 250),
        "X-Simulate-Segment": "SWIFT",
        "X-Simulate-Port":    1433,
        "X-Simulate-Packet-Score": round(random.uniform(0.6, 0.9), 2),     # High SQL injection payload signs
        "X-Simulate-Behavior-Score": round(random.uniform(0.85, 0.99), 2), # CRITICAL: Anomalous RDP logon to DB
    }
    print(f"{COLORS['CONSOLE']}[CONSOLE] 🔴 Firing SWIFT SQL PROBE from {ip}...{COLORS['RESET']}")
    send_traffic(ip, headers)

def trigger_c2():
    ip = get_random_internal_ip()
    pkts = random.randint(3, 45)
    headers = {
        "X-Simulate-Packets": pkts,
        "X-Simulate-Bytes":   pkts * random.randint(50, 400),
        "X-Simulate-Segment": random.choice(["WORKSTATION", "GUEST_WIFI", "IOT"]),
        "X-Simulate-Port":    853,
        "X-Simulate-JA3":     random.choice(["c7d1e3f2a4b6c8d0", "e7d1e3f2a4b6c8d1", "a7d1e3f2a4b6c8d2"]), 
        "X-Simulate-Packet-Score": round(random.uniform(0.9, 0.99), 2),    # CRITICAL: Malicious JA3 detected in SSL handshake
        "X-Simulate-Behavior-Score": round(random.uniform(0.2, 0.5), 2),   # Mildly suspicious background task
    }
    print(f"{COLORS['CONSOLE']}[CONSOLE] 🔴 Firing C2 BEACON from {ip}...{COLORS['RESET']}")
    send_traffic(ip, headers)

def view_blocklist():
    try:
        req = urllib.request.Request(TARGET_URL + "/api/blocklist", method="GET")
        resp = urllib.request.urlopen(req, timeout=2)
        import json
        blocked = json.loads(resp.read().decode('utf-8'))
        print(f"\n{COLORS['CONSOLE']}[CONSOLE] 🛡️  ACTIVE FIREWALL BLOCKLIST ({len(blocked)} IPs):")
        for ip in blocked:
            print(f"           - {ip}")
        if not blocked:
            print("           (No IPs are currently blocked)")
        print(f"{COLORS['RESET']}")
    except Exception as e:
        print(f"{COLORS['CONSOLE']}[CONSOLE] ⚠️ Error fetching blocklist: {e}{COLORS['RESET']}")

def print_menu():
    print(f"\n{COLORS['CONSOLE']}==============================================================")
    print(" INTERACTIVE ATTACK CONSOLE")
    print("==============================================================")
    print("  [1] Send Normal Benign Traffic (Employee)")
    print("  [2] Launch Data Exfiltration Attack (External)")
    print("  [3] Launch SWIFT SQL Probe (Internal)")
    print("  [4] Launch C2 Beacon (Internal)")
    print("  [5] View Blocked IPs")
    print("  [q] Quit Demo")
    print(f"=============================================================={COLORS['RESET']}")

def main():
    print("\033[1;36m")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     GIBL CORE BANKING — LIVE IDS DEMONSTRATION          ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║  Server  → Banking application on port 8080             ║")
    print("║  IDS     → ML-powered intrusion detection (XGBoost)     ║")
    print("║  Sim     → Interactive Attack Console                   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("\033[0m")

    base = os.path.dirname(os.path.abspath(__file__))
    py   = sys.executable

    # 1. Server
    server = subprocess.Popen(
        [py, "-u", os.path.join(base, "target_server.py")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        cwd=os.path.join(base, "..")
    )
    threading.Thread(target=stream_output,
                     args=(server, "SERVER", COLORS["SERVER"]),
                     daemon=True).start()
    time.sleep(2)

    # 2. IDS Engine
    ids = subprocess.Popen(
        [py, "-u", os.path.join(base, "live_ids.py")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        cwd=os.path.join(base, "..")
    )
    threading.Thread(target=stream_output,
                     args=(ids, "IDS", COLORS["IDS"]),
                     daemon=True).start()
    time.sleep(3)

    # 3. Interactive Loop
    try:
        while True:
            print_menu()
            choice = input(f"{COLORS['CONSOLE']}Select payload > {COLORS['RESET']}").strip().lower()
            
            if choice == '1':
                trigger_benign()
            elif choice == '2':
                trigger_exfil()
            elif choice == '3':
                trigger_swift()
            elif choice == '4':
                trigger_c2()
            elif choice == '5':
                view_blocklist()
            elif choice == 'q':
                break
            else:
                print(f"{COLORS['CONSOLE']}[CONSOLE] Invalid choice.{COLORS['RESET']}")
                
            # small delay to allow logs to print before re-drawing menu
            time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        print("\n\033[1;31m[DEMO] Shutting down all components...\033[0m")
        for p in [ids, server]:
            p.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
