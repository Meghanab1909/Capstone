import csv
import os
import subprocess
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import requests

LABELED_CSV = "logs/traffic_labeled.csv"
GATEWAY_LOG = "logs/gateway.log"
AI_SCRIPT = "/home/meghana/iot-honeynet/ai_engine/hybrid_ai.py"

REAL_SERVER = "http://localhost:5000"
HONEYPOT_SERVER = "http://localhost:5002"

GATEWAY_PORT = 8080


# -------------------------------------------------------
# 1. Write a NEW FLOW ENTRY (unlabeled) before AI runs
# -------------------------------------------------------
def write_flow(flow_row):
    header = [
        "req_id","src_ip","dst_ip","src_port","dst_port","protocol",
        "src_bytes","dst_bytes","flow_duration","packet_count",
        "conn_state","timestamp"
    ]

    exists = os.path.exists(LABELED_CSV)

    with open(LABELED_CSV, "a") as f:
        w = csv.writer(f)
        # Write header only if file is new
        if not exists:
            w.writerow(header)
        # Append the new unlabeled flow
        w.writerow(flow_row)


# -------------------------------------------------------
# 2. Read label for req_id (last decision from hybrid_ai.py)
# -------------------------------------------------------
def get_label(req_id):
    if not os.path.exists(LABELED_CSV):
        return 0

    df = list(csv.reader(open(LABELED_CSV)))
    header = df[0]
    rows = df[1:]

    req_idx = header.index("req_id")
    label_idx = header.index("label") if "label" in header else None

    if label_idx is None:
        return 0

    # Search from newest to oldest
    for row in reversed(rows):
        # Skip unlabeled rows (blank label)
        if len(row) <= label_idx or row[label_idx].strip() == "":
            continue

        if str(row[req_idx]) == str(req_id):
            try:
                return int(row[label_idx])
            except:
                continue

    return 0


# -------------------------------------------------------
# 3. Log gateway decision (no changes needed)
# -------------------------------------------------------
def log_event(req_id, src_ip, label, target):
    if label == 0:
        ai_label = "benign"
        decision = "allow"
        target = REAL_SERVER
    else:
        ai_label = "suspicious"
        decision = "redirect"
        target = HONEYPOT_SERVER

    entry = {
        "timestamp": str(datetime.now()),
        "req_id": int(req_id),
        "src_ip": str(src_ip),
        "ai_label": ai_label,
        "decision": decision,
        "forward_to": target
    }

    with open(GATEWAY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# -------------------------------------------------------
# 4. Gateway HTTP handler (majorly updated)
# -------------------------------------------------------
class GatewayHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]

        # -----------------------------------------------
        # CREATE REAL-TIME FLOW ENTRY
        # -----------------------------------------------
        req_id = int(time.time() * 1000)  # unique per request
        src_ip = client_ip
        dst_ip = "192.168.0.1"            # gateway or real IP
        src_port = self.client_address[1]                     
        dst_port = GATEWAY_PORT
        protocol = 6                      # assume TCP
        src_bytes = 0                     # placeholder unless monitored
        dst_bytes = 0
        flow_duration = 0.001             # placeholder
        packet_count = 1                  # at least 1 packet
        conn_state = "SF"                 # normal TCP SYN-ACK
        timestamp = time.time()

        # Build the flow row
        flow = [
            req_id, src_ip, dst_ip, src_port, dst_port, protocol,
            src_bytes, dst_bytes, flow_duration, packet_count,
            conn_state, timestamp
        ]

        # -----------------------------------------------
        # WRITE UNLABELED FLOW FOR AI ENGINE
        # -----------------------------------------------
        write_flow(flow)

        # -----------------------------------------------
        # RUN AI ENGINE (hybrid_ai.py)
        # -----------------------------------------------
        try:
            subprocess.run(["python3", AI_SCRIPT], timeout=5)
        except Exception as e:
            print("AI Error:", e)

        time.sleep(0.1)   # ensure new label is written

        # -----------------------------------------------
        # READ LABEL
        # -----------------------------------------------
        label = get_label(req_id)

        # -----------------------------------------------
        # ROUTING DECISION
        # -----------------------------------------------
        if label == 0:
            target = REAL_SERVER
        else:
            target = HONEYPOT_SERVER

        log_event(req_id, src_ip, label, target)

        # -----------------------------------------------
        # FORWARD REQUEST
        # -----------------------------------------------
        try:
            r = requests.get(target)
            content = r.text
        except Exception as e:
            content = str(e)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(content.encode())
        
# -------------------------------------------------------
# MAIN
# -------------------------------------------------------
def main():
    server = HTTPServer(("0.0.0.0", GATEWAY_PORT), GatewayHandler)
    print(f"[+] Gateway running on port {GATEWAY_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

