import http.server
import socketserver
import json
import time
import os
import threading
from urllib.parse import urlparse
import random

PORT = 8080
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_netflow.log")
ALERTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_alerts.log")
BLOCKLIST = set()

def get_random_external_ip():
    return f"{random.choice([45, 82, 185, 203])}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(1, 254)}"

def get_random_internal_ip():
    return f"10.{random.randint(10, 50)}.{random.randint(1, 5)}.{random.randint(20, 250)}"

class DemoRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # We handle logging explicitly
        pass

    def _append_netflow(self, src_ip):
        """Generates a synthetic netflow log entry based on headers or defaults, including simulated agent scores."""
        # Read spoofed metadata
        packets = int(self.headers.get("X-Simulate-Packets", random.randint(5, 20)))
        bytes_sent = int(self.headers.get("X-Simulate-Bytes", random.randint(500, 1500)))
        segment = self.headers.get("X-Simulate-Segment", "WORKSTATION")
        port = int(self.headers.get("X-Simulate-Port", 8080))
        ja3_hash = self.headers.get("X-Simulate-JA3", "UNKNOWN")
        sim_packet_score = float(self.headers.get("X-Simulate-Packet-Score", 0.05))
        sim_behavior_score = float(self.headers.get("X-Simulate-Behavior-Score", 0.05))
        
        self._write_flow_row(src_ip, packets, bytes_sent, segment, port, ja3_hash, sim_packet_score, sim_behavior_score)

    def _write_flow_row(self, src_ip, packets, bytes_sent, segment, port, ja3_hash, sim_packet_score, sim_behavior_score, dst_ip="10.0.0.1"):
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                LOG_FILE_HEADERS = "flow_id,src_ip,dst_ip,start_time,duration_sec,packets_sent,packets_recv,bytes_sent,bytes_recv,segment,is_internal_src,is_internal_dst,dst_port,tcp_flags,ja3_hash,sim_packet_score,sim_behavior_score\n"
                f.write(LOG_FILE_HEADERS)
        
        flow_id = f"flow_{int(time.time()*1000)}_{random.randint(1000, 9999)}"
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        is_int = 'True' if (src_ip.startswith('10.') or src_ip.startswith('192.168.') or src_ip.startswith('172.16.')) else 'False'
        
        line = f"{flow_id},{src_ip},{dst_ip},{start_time},1.5,{packets},10,{bytes_sent},2000,{segment},{is_int},True,{port},S,{ja3_hash},{sim_packet_score},{sim_behavior_score}\n"
        with open(LOG_FILE, "a") as f:
            f.write(line)

    def _append_simulated_netflow(self, type_name):
        def run_simulation():
            if type_name == 'benign':
                src_ip = f"192.168.1.{random.randint(100, 115)}"
                packets = random.randint(5, 15)
                bytes_sent = packets * random.randint(100, 1500)
                self._write_flow_row(src_ip, packets, bytes_sent, "WORKSTATION", 443, "UNKNOWN", round(random.uniform(0.01, 0.15), 2), round(random.uniform(0.01, 0.15), 2))
            elif type_name == 'exfil':
                src_ip = get_random_external_ip()
                packets = random.randint(1000, 75000)
                bytes_sent = packets * random.randint(2, 60)
                segment = random.choice(["CORE_BANKING", "DMZ", "WORKSTATION"])
                port = random.choice([8080, 443, 3389, 22, 21])
                self._write_flow_row(src_ip, packets, bytes_sent, segment, port, "UNKNOWN", round(random.uniform(0.1, 0.3), 2), round(random.uniform(0.2, 0.4), 2))
            elif type_name == 'swift':
                src_ip = get_random_internal_ip()
                dst_ip = f"10.30.1.{20 + random.randint(0, 5)}"
                packets = random.randint(50, 1500)
                bytes_sent = packets * random.randint(10, 250)
                self._write_flow_row(src_ip, packets, bytes_sent, "SWIFT", 1433, "UNKNOWN", round(random.uniform(0.6, 0.9), 2), round(random.uniform(0.85, 0.99), 2), dst_ip=dst_ip)
            elif type_name == 'c2':
                src_ip = get_random_internal_ip()
                packets = random.randint(3, 45)
                bytes_sent = packets * random.randint(50, 400)
                segment = random.choice(["WORKSTATION", "GUEST_WIFI", "IOT"])
                port = 853
                ja3 = random.choice(["c7d1e3f2a4b6c8d0", "e7d1e3f2a4b6c8d1", "a7d1e3f2a4b6c8d2"])
                self._write_flow_row(src_ip, packets, bytes_sent, segment, port, ja3, round(random.uniform(0.9, 0.99), 2), round(random.uniform(0.2, 0.5), 2))
                    
        threading.Thread(target=run_simulation, daemon=True).start()

    def do_POST(self):
        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0])
        if client_ip in BLOCKLIST:
            self.send_error(403, "Blocked by IDS")
            return
            
        path = urlparse(self.path).path
        if path == '/api/block':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            ip_to_block = data.get('ip')
            if ip_to_block and ip_to_block not in BLOCKLIST and ip_to_block not in ('127.0.0.1', 'localhost', '::1'):
                BLOCKLIST.add(ip_to_block)
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "blocked"}')
            return

        if path == '/api/unblock':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            ip_to_unblock = data.get('ip')
            if ip_to_unblock in BLOCKLIST:
                BLOCKLIST.remove(ip_to_unblock)
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "unblocked"}')
            return

        if path == '/api/trigger':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            type_name = data.get('type')
            self._append_simulated_netflow(type_name)
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "triggered"}')
            return

        # normal POST
        self.send_response(200)
        self.end_headers()
        body = b'{"status": "success"}'
        self.wfile.write(body)
        
        if not path.startswith('/api/'):
            self._append_netflow(client_ip)

    def do_GET(self):
        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0])
        if client_ip in BLOCKLIST:
            self.send_error(403, "Forbidden")
            return
            
        path = urlparse(self.path).path
        if path in ('/', '/dashboard', '/index.html'):
            try:
                html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
                with open(html_path, "rb") as fh:
                    body = fh.read()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(body)
                return
            except Exception as e:
                self.send_error(500, f"Error loading index.html: {e}")
                return

        if path == '/api/blocklist':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(BLOCKLIST)).encode('utf-8'))
            return

        if path == '/api/alerts':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            alerts = []
            if os.path.exists(ALERTS_FILE):
                try:
                    with open(ALERTS_FILE, "r") as f:
                        # read last 50 lines
                        lines = f.readlines()[-50:]
                        alerts = [json.loads(line.strip()) for line in lines if line.strip()]
                except Exception:
                    pass
            self.wfile.write(json.dumps(alerts).encode('utf-8'))
            return

        if path == '/api/logs':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r") as f:
                        lines = f.readlines()
                        header = lines[0].strip().split(",") if lines else []
                        body_lines = lines[1:][-50:] # last 50 entries
                        for line in body_lines:
                            if line.strip():
                                logs.append(dict(zip(header, line.strip().split(","))))
                except Exception:
                    pass
            self.wfile.write(json.dumps(logs).encode('utf-8'))
            return
            
        if path == '/login':
            body = b"Login Page"
        elif path == '/transfer':
            body = b"Fund Transfer Initialized"
        else:
            body = b"Welcome to GIBL Target Server"
            
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(body)
        
        if not path.startswith('/api/') and path not in ('/', '/dashboard', '/index.html'):
            self._append_netflow(client_ip)

if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("0.0.0.0", PORT), DemoRequestHandler)
    print(f"Target Server listening on port {PORT}...")
    server.serve_forever()
