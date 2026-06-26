import csv
import os
import subprocess
import time
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
from collections import defaultdict
import requests
from requests.adapters import HTTPAdapter
import socket
from urllib.parse import urlparse, parse_qs

LABELED_CSV     = "logs/traffic_labeled.csv"
GATEWAY_LOG     = "logs/gateway.log"
AI_ANALYSIS_LOG = "logs/ai_analysis.log"
AI_SCRIPT       = "/home/meghana/iot-honeynet/ai_engine/hybrid_ai.py"
GATEWAY_IP = socket.gethostbyname(socket.gethostname())

# -----------------------------------------------------------------------
# SERVER POOLS
# gateway.py runs on the HOST. Containers are reachable via 127.0.0.1
# on their mapped host ports.
#
#   real_iot_c1  → 127.0.0.1:5000  (container :5000)
#   real_iot_c2  → 127.0.0.1:5003  (container :5000)
#   real_iot_c3  → 127.0.0.1:5006  (container :5000)
#   real_iot_c4  → 127.0.0.1:5009  (container :5000)
#   honeypot_c1  → 127.0.0.1:5002  (container :80 — beelzebub)
#   honeypot_c2  → 127.0.0.1:5004  (container :80 — beelzebub)
#   dummy_iot_c1 → 127.0.0.1:5001  (container :5001)
# -----------------------------------------------------------------------
REAL_SERVERS     = ["http://127.0.0.1:5000", "http://127.0.0.1:5003",
                    "http://127.0.0.1:5006", "http://127.0.0.1:5009"]
HONEYPOT_SERVERS = ["http://127.0.0.1:5002", "http://127.0.0.1:5004"]
DUMMY_SERVERS    = ["http://127.0.0.1:5001"]

# -----------------------------------------------------------------------
# Ollama — runs on the HOST, called directly from gateway.py
# (gateway.py is also on the host so localhost works fine here)
# -----------------------------------------------------------------------
OLLAMA_URL   = "http://127.0.0.1:11434/v1/chat/completions"
OLLAMA_MODEL = "llama3:latest"   # must match `ollama list` output exactly

_rr_index  = {"real": 0, "honeypot": 0, "dummy": 0}
_dead_until: dict = {}
DEAD_NODE_COOLDOWN = 30

_ip_counts = defaultdict(lambda: {"benign": 0, "suspicious": 0})

GATEWAY_PORT    = 8080
CONNECT_TIMEOUT = 5
READ_TIMEOUT    = 200


# -----------------------------------------------------------------------
# HTTP session
# -----------------------------------------------------------------------
def _make_session() -> requests.Session:
    s = requests.Session()
    s.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=0))
    return s

_session = _make_session()


# -----------------------------------------------------------------------
# LOAD BALANCER
# -----------------------------------------------------------------------
def _is_dead(url): return time.time() < _dead_until.get(url, 0)
def _mark_dead(url):
    _dead_until[url] = time.time() + DEAD_NODE_COOLDOWN
    print(f"[LB] Dead for {DEAD_NODE_COOLDOWN}s: {url}")

def next_server(pool: str):
    servers = {"real": REAL_SERVERS, "honeypot": HONEYPOT_SERVERS, "dummy": DUMMY_SERVERS}[pool]
    for _ in range(len(servers)):
        idx = _rr_index[pool] % len(servers)
        _rr_index[pool] = idx + 1
        if not _is_dead(servers[idx]):
            return servers[idx], idx
    print(f"[LB] All {pool} nodes dead — forcing first")
    _dead_until.clear()
    return servers[0], 0


# -----------------------------------------------------------------------
# STARTUP HEALTH CHECK
# -----------------------------------------------------------------------
def check_pool(name, servers):
    ok = []
    for url in servers:
        try:
            r = requests.get(url + "/", timeout=(2, 3))
            print(f"  ✓  {url}  →  HTTP {r.status_code}")
            ok.append(url)
        except Exception as e:
            print(f"  ✗  {url}  →  {type(e).__name__}: {e}")
    if not ok:
        print(f"[WARN] Pool '{name}': NO nodes reachable. Check 'docker compose ps'.")
    return ok

def check_ollama(retries=5, delay=3):
    '''Wait for Ollama to be ready — avoids race condition at startup.'''
    print("Ollama (127.0.0.1:11434):")
    for attempt in range(retries):
        try:
            r = requests.get("http://127.0.0.1:11434/api/tags", timeout=(3, 5))
            data = r.json()
            if not isinstance(data, dict):
                raise ValueError(f"unexpected response type: {type(data)}")
            models = [m["name"] for m in data.get("models", [])]
            if any(OLLAMA_MODEL in m for m in models):
                print(f"  ✓  Ollama ready — model '{OLLAMA_MODEL}' found")
                return
            else:
                print(f"  ✗  Ollama up but '{OLLAMA_MODEL}' not pulled. Run: ollama pull {OLLAMA_MODEL}")
                return
        except Exception as e:
            if attempt < retries - 1:
                print(f"  ⟳  Ollama not ready yet (attempt {attempt+1}/{retries}): {e}")
                time.sleep(delay)
            else:
                print(f"  ✗  Ollama unreachable after {retries} attempts: {e}")

def startup_checks(retries=5, delay=3):
    print("\n[GATEWAY] Startup connectivity check")
    print("─" * 54)
    for attempt in range(retries):
        try:
            print(f"Real pool ({len(REAL_SERVERS)} nodes):")
            check_pool("real", REAL_SERVERS)
            print(f"Honeypot pool ({len(HONEYPOT_SERVERS)} nodes):")
            check_pool("honeypot", HONEYPOT_SERVERS)
            print(f"Dummy pool ({len(DUMMY_SERVERS)} node):")
            check_pool("dummy", DUMMY_SERVERS)
            check_ollama()
            print("─" * 54 + "\n")
        except Exception as e:
            if attempt < retries - 1:
                print(f"  ⟳  Containers not ready yet (attempt {attempt+1}/{retries}): {e}")
                time.sleep(delay)
            else:
                print(f"  ✗  Check docker ps -a")


# -----------------------------------------------------------------------
# PATH/PAYLOAD FEATURES — the actual fix for the RF model being blind to
# request content. Every prior feature (dst_port, conn_state, proto, etc.)
# is identical for every request through this gateway, so the model had
# nothing to discriminate on. These are derived from the same keyword
# groups already used in gateway_llm_analysis(), for consistency.
# -----------------------------------------------------------------------
def extract_path_features(path: str, body: bytes) -> dict:
    body_str = body.decode("utf-8", errors="replace") if body else ""
    combined = (path + " " + body_str).lower()

    return {
        "path_length": len(path),
        "has_sql_pattern": int(any(
            x in combined for x in ["select", "union", "drop", "insert", "where", "'", "--"]
        )),
        "has_xss_pattern": int(any(
            x in combined for x in ["<script", "alert(", "onerror", "javascript:"]
        )),
        "has_traversal_pattern": int(any(
            x in combined for x in ["../", "%2e%2e", "passwd", "/etc/", "/proc/"]
        )),
        "has_rce_pattern": int(any(
            x in combined for x in ["cmd=", "exec", "shell", "wget", "curl", "bash", "&&", "|"]
        )),
        "has_recon_cve_pattern": int(any(
            x in combined for x in ["wp-", "phpmyadmin", "xmlrpc", ".env", ".git", "admin", "login"]
        )),
    }


# -----------------------------------------------------------------------
# FLOW CSV
# -----------------------------------------------------------------------
# FLOW CSV
# -----------------------------------------------------------------------
def write_flow(row):
    # This MUST match the actual on-disk header in traffic_labeled.csv,
    # not just "whatever columns the gateway happens to populate" - label,
    # duration, missed_bytes, src_pkts, src_ip_bytes, dst_pkts, dst_ip_bytes
    # already exist at these exact positions from earlier in the project
    # (label gets filled in later by hybrid_ai.py; the rest are always NaN -
    # the gateway has never measured them, see Known Gateway Limitations).
    # New path/payload columns go at the TRUE end, after dst_ip_bytes.
    header = ["req_id","src_ip","dst_ip","src_port","dst_port","protocol",
              "src_bytes","dst_bytes","flow_duration","packet_count","conn_state","timestamp",
              "label","duration","missed_bytes","src_pkts","src_ip_bytes","dst_pkts","dst_ip_bytes",
              "http_method","path_length","has_sql_pattern","has_xss_pattern",
              "has_traversal_pattern","has_rce_pattern","has_recon_cve_pattern"]
    os.makedirs(os.path.dirname(LABELED_CSV), exist_ok=True)
    exists = os.path.exists(LABELED_CSV)
    with open(LABELED_CSV, "a") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(header)
        w.writerow(row)

def get_label(req_id):
    if not os.path.exists(LABELED_CSV):
        return 0
    rows = list(csv.reader(open(LABELED_CSV)))
    if len(rows) < 2:
        return 0
    header, data = rows[0], rows[1:]
    ri = header.index("req_id")
    li = header.index("label") if "label" in header else None
    if li is None:
        return 0
    for row in reversed(data):
        if len(row) <= li or row[li].strip() == "":
            continue
        if str(row[ri]) == str(req_id):
            try: return int(row[li])
            except: continue
    return 0


# -----------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------
def log_event(req_id, src_ip, label, target, cluster_idx, pool):
    entry = {
        "timestamp":  str(datetime.now()),
        "req_id":     int(req_id),
        "src_ip":     str(src_ip),
        "ai_label":   "benign" if label == 0 else "suspicious",
        "decision":   "allow"  if label == 0 else "redirect",
        "forward_to": target,
        "pool":       pool,
        "cluster":    cluster_idx + 1,
    }
    os.makedirs(os.path.dirname(GATEWAY_LOG), exist_ok=True)
    with open(GATEWAY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# -----------------------------------------------------------------------
# HONEYPOT PAGE TEMPLATE — static shell + one dynamic log line
#
# Beelzebub's LLM no longer generates full HTML (too slow, unreliable -
# see project history). It outputs ONE short JSON snippet describing the
# request; this template wraps it in the same styled Edge Device Portal
# used for the static landing page, so suspicious traffic gets a visually
# consistent, fast, and genuinely dynamic-looking response.
# Placeholders use __TOKEN__ (not .format()) to avoid clashing with CSS braces.
# -----------------------------------------------------------------------
HONEYPOT_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Edge Device Portal</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#06080b;--panel:#0b0e13;--panel-alt:#0e1218;
      --border:#1a2430;--border-hi:#253444;
      --green:#00e87a;--green-dim:#00512b;
      --amber:#f5a623;--amber-dim:#7a5010;
      --red:#ff3b55;--red-dim:#6b1020;
      --blue:#38b6ff;--blue-dim:#0d3d5a;
      --muted:#3a5060;--text:#b8cad6;--text-hi:#ddeaf2;
    }
    html,body{background:var(--bg);color:var(--text);font-family:'Courier New',Courier,monospace;min-height:100vh}
    body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.08) 2px,rgba(0,0,0,.08) 4px);pointer-events:none;z-index:200}
    .page{max-width:780px;margin:0 auto;padding:2rem 1.2rem;display:flex;flex-direction:column;gap:1.1rem;animation:rise .5s ease both}
    @keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
    .card{border:1px solid var(--border);background:var(--panel);position:relative}
    .card::before,.card::after,.c-br,.c-bl{content:'';position:absolute;width:12px;height:12px;border-style:solid;border-color:var(--green)}
    .card::before{top:-1px;left:-1px;border-width:2px 0 0 2px}
    .card::after{top:-1px;right:-1px;border-width:2px 2px 0 0}
    .c-br{bottom:-1px;right:-1px;border-width:0 2px 2px 0}
    .c-bl{bottom:-1px;left:-1px;border-width:0 0 2px 2px}
    .topbar{display:flex;align-items:center;justify-content:space-between;padding:.7rem 1.1rem;border-bottom:1px solid var(--border);background:#080b0f}
    .topbar-left{display:flex;align-items:center;gap:.75rem}
    .logo{width:28px;height:28px;border:2px solid var(--green);display:grid;place-items:center;flex-shrink:0}
    .logo::before{content:'';width:10px;height:10px;background:var(--green);clip-path:polygon(50% 0%,100% 100%,0% 100%)}
    .device-id{font-size:.6rem;color:var(--muted);letter-spacing:.12em;text-transform:uppercase;line-height:1.3}
    .device-name{font-size:.88rem;color:var(--text-hi);letter-spacing:.05em}
    .pills{display:flex;gap:.5rem}
    .pill{display:flex;align-items:center;gap:.35rem;font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;padding:.25rem .6rem;border:1px solid}
    .pill-green{border-color:var(--green-dim);color:var(--green)}
    .dot{width:6px;height:6px;border-radius:50%;animation:blink 1.8s ease-in-out infinite}
    .dot-green{background:var(--green)}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
    .subbar{padding:.4rem 1.1rem;border-bottom:1px solid var(--border);background:rgba(0,0,0,.25);display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
    .crumb{font-size:.62rem;color:var(--muted);letter-spacing:.08em}
    .crumb em{color:var(--green);font-style:normal}
    .tag{font-size:.55rem;letter-spacing:.1em;text-transform:uppercase;padding:.12rem .45rem;border:1px solid var(--border);color:var(--muted)}
    .metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
    .metric{background:var(--panel);padding:.85rem 1rem;display:flex;flex-direction:column;gap:.2rem}
    .m-label{font-size:.55rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted)}
    .m-val{font-size:1.6rem;line-height:1;font-family:'Courier New',monospace}
    .m-sub{font-size:.55rem;color:var(--muted)}
    .val-green{color:var(--green)}.val-amber{color:var(--amber)}.val-blue{color:var(--blue)}
    .sec-head{display:flex;align-items:center;justify-content:space-between;padding:.45rem .85rem;border-bottom:1px solid var(--border);background:rgba(0,0,0,.3)}
    .sec-title{font-size:.58rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
    .sec-badge{font-size:.55rem;letter-spacing:.1em;text-transform:uppercase;padding:.1rem .4rem;border:1px solid var(--border);color:var(--muted);background:transparent}
    .info-body{padding:.8rem .85rem;display:flex;flex-direction:column;gap:.4rem}
    .info-row{display:flex;justify-content:space-between;align-items:center;padding:.45rem 0;border-bottom:1px solid var(--border)}
    .info-row:last-child{border-bottom:none}
    .info-key{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
    .info-val{font-size:.75rem;color:var(--text)}.info-val-g{color:var(--green)}
    .log-body{padding:.7rem .85rem;font-size:.68rem;line-height:1.95;color:var(--muted);background:#070a0d}
    .log-line{display:flex;gap:.85rem}
    .log-time{color:#1e3040;min-width:74px}
    .log-ok{color:var(--green)}.log-info{color:var(--blue)}.log-warn{color:var(--amber)}.log-err{color:var(--red)}
    .actions{padding:.85rem;display:flex;gap:.65rem;flex-wrap:wrap}
    .btn{font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;padding:.5rem 1rem;border:1px solid;cursor:pointer;background:transparent;text-decoration:none;display:inline-block;transition:background .15s,color .15s}
    .btn-green{border-color:var(--green);color:var(--green)}
    .btn-green:hover{background:var(--green);color:var(--bg)}
    .btn-muted{border-color:var(--border);color:var(--muted)}
    .btn-muted:hover{border-color:var(--muted);color:var(--text)}
    .footer{border-top:1px solid var(--border);padding:.55rem 1.1rem;background:#080b0f;display:flex;justify-content:space-between;align-items:center}
    .footer-txt{font-size:.55rem;color:var(--muted);letter-spacing:.07em}
    .led-row{display:flex;gap:.4rem}
    .led{width:7px;height:7px;border-radius:50%}
    .led-g{background:var(--green);box-shadow:0 0 4px var(--green);animation:blink 2s infinite}
    .led-a{background:var(--amber);box-shadow:0 0 4px var(--amber);animation:blink 3s infinite .5s}
    .led-off{background:#111}
  </style>
</head>
<body>
<div class="page">
  <div class="card">
    <div class="c-br"></div><div class="c-bl"></div>
    <div class="topbar">
      <div class="topbar-left">
        <div class="logo"></div>
        <div>
          <div class="device-id">Model: HPBB-4F2A &nbsp;|&nbsp; SN-0xBEE1</div>
          <div class="device-name">Edge Device Portal</div>
        </div>
      </div>
      <div class="pills"><div class="pill pill-green"><div class="dot dot-green"></div>Online</div></div>
    </div>
    <div class="subbar">
      <div class="crumb">root / <em>device</em> / status</div>
      <div class="tag">fw v2.4.53-deb</div>
      <div class="tag">eth0 &middot; 192.168.1.42</div>
      <div class="tag">IPv4</div>
    </div>
    <div class="metrics">
      <div class="metric"><div class="m-label">System Status</div><div class="m-val val-green">OK</div><div class="m-sub">All subsystems nominal</div></div>
      <div class="metric"><div class="m-label">Signal Strength</div><div class="m-val val-blue">-62</div><div class="m-sub">dBm &middot; RSSI Good</div></div>
      <div class="metric"><div class="m-label">Uptime</div><div class="m-val val-amber">00:01</div><div class="m-sub">00d 00h 01m &middot; since last boot</div></div>
    </div>
    <div class="sec-head"><span class="sec-title">Device Info</span><span class="sec-badge">SYS &middot; RUNTIME</span></div>
    <div class="info-body">
      <div class="info-row"><span class="info-key">Model</span><span class="info-val">HPBB-4F2A</span></div>
      <div class="info-row"><span class="info-key">Firmware</span><span class="info-val">v2.4.53-deb</span></div>
      <div class="info-row"><span class="info-key">IP Address</span><span class="info-val">192.168.1.42</span></div>
      <div class="info-row"><span class="info-key">MAC</span><span class="info-val">b8:27:eb:4f:2a:c1</span></div>
      <div class="info-row"><span class="info-key">Protocol</span><span class="info-val">HTTP &middot; SSH &middot; TCP &middot; IPv4</span></div>
      <div class="info-row"><span class="info-key">Status</span><span class="info-val info-val-g">Operational</span></div>
    </div>
    <div class="sec-head"><span class="sec-title">System Log</span><span class="sec-badge">RUNTIME &middot; LIVE</span></div>
    <div class="log-body">
      <div class="log-line"><span class="log-time">00:00:01</span><span class="log-ok">[BOOT]</span><span>Kernel loaded. Mounting filesystems...</span></div>
      <div class="log-line"><span class="log-time">00:00:02</span><span class="log-ok">[INIT]</span><span>Network interface eth0 UP</span></div>
      <div class="log-line"><span class="log-time">00:00:03</span><span class="log-info">[DHCP]</span><span>Address acquired: 192.168.1.42</span></div>
      <div class="log-line"><span class="log-time">00:00:04</span><span class="log-ok">[SVC]</span><span>Core services initialised</span></div>
      <div class="log-line"><span class="log-time">00:00:05</span><span class="log-ok">[HTTP]</span><span>Listener ready on :80</span></div>
      <div class="log-line"><span class="log-time">00:00:06</span><span class="log-ok">[NET]</span><span>All interfaces nominal &mdash; portal UP</span></div>
      <div class="log-line"><span class="log-time">__NOW__</span><span class="__STATUS_CLASS__">[__STATUS_TAG__]</span><span>__LOG_LINE__</span></div>
    </div>
    <div class="actions">
      <a href="/status" class="btn btn-green">&#9654; Status</a>
      <button class="btn btn-muted" onclick="location.reload()">&#8634; Refresh</button>
      <button class="btn btn-green" onclick="openSSHConsole()">&#128187; SSH Console</button>
    </div>
    <div class="footer">
      <div class="footer-txt">HPBB-4F2A &middot; 192.168.1.42 &middot; fw v2.4.53-deb</div>
      <div class="led-row">
        <div class="led led-g" title="Power"></div>
        <div class="led led-a" title="Activity"></div>
        <div class="led led-off" title="No Error"></div>
      </div>
    </div>
  </div>
</div>
<script>
  function openSSHConsole() {
    window.open('http://' + window.location.hostname + ':8000/ssh-terminal', '_blank');
  }
</script>
</body>
</html>"""

_STATUS_CLASS_MAP = {"ok": "log-ok", "warn": "log-warn", "err": "log-err"}
_STATUS_TAG_MAP   = {"ok": "INFO", "warn": "ALERT", "err": "BLOCKED"}

def render_honeypot_page(log_line: str, status: str) -> str:
    status = status if status in _STATUS_CLASS_MAP else "warn"
    now = datetime.now().strftime("%H:%M:%S")
    return (HONEYPOT_PAGE_TEMPLATE
            .replace("__NOW__", now)
            .replace("__STATUS_CLASS__", _STATUS_CLASS_MAP[status])
            .replace("__STATUS_TAG__", _STATUS_TAG_MAP[status])
            .replace("__LOG_LINE__", log_line.replace("<", "&lt;").replace(">", "&gt;")))


def parse_honeypot_snippet(raw_content: str):
    """
    Get a usable log line out of Beelzebub's response. Prefers the
    structured {"log_line":...,"status":...} JSON if the model produced
    it, but falls back to the model's own freeform text (first line) if
    not - in practice the model often ignores the JSON instruction and
    generates in-character decoy text directly (e.g. a fake MySQL error
    for a SQLi-looking request), which is usually GOOD bait content, just
    not in the format asked for. Returns (log_line, status, format) where
    format is "json" or "freeform". Only (None, None, None) if truly empty.
    """
    text = raw_content.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(0))
            return (data.get("log_line", "Unusual request pattern detected"),
                    data.get("status", "warn"), "json")
        except json.JSONDecodeError:
            pass  # not valid JSON - fall through to freeform handling

    first_line = next((l.strip() for l in text.splitlines() if l.strip()), "")
    if first_line:
        return first_line[:120], "warn", "freeform"
    return None, None, None


# -----------------------------------------------------------------------
# ANALYSIS BLOCK — extracted from beelzebub LLM response
# -----------------------------------------------------------------------
ANALYSIS_RE = re.compile(r"<!--ANALYSIS:\s*(\{.*?\})\s*-->", re.DOTALL)

def extract_analysis(text: str):
    m = ANALYSIS_RE.search(text)
    if not m:
        return text, None
    clean = text[:m.start()].rstrip()
    try:
        analysis = json.loads(m.group(1))
        analysis["analysis_source"] = "honeypot_llm"   # ← add this
        return clean, analysis
    except json.JSONDecodeError as e:
        return clean, {"raw": m.group(1), "parse_error": str(e)}

def persist_analysis(req_id, src_ip, flow_row, analysis: dict, honeypot_engagement: dict = None):
    record = {
        "timestamp": str(datetime.now()),
        "req_id":    int(req_id),
        "src_ip":    str(src_ip),
        "flow": {"src_port": flow_row[3], "dst_port": flow_row[4],
                 "protocol": flow_row[5], "conn_state": flow_row[10],
                 "packet_count": flow_row[9]},
        # What Beelzebub's own LLM generated for the visible page - separate
        # from "analysis" below, which is always the gateway's own call.
        # Neither one replaces or negates the other; they do different jobs.
        "honeypot_engagement": honeypot_engagement or {"source": "honeypot_llm", "log_line": None, "format": None},
        "analysis":  analysis,
    }
    os.makedirs(os.path.dirname(AI_ANALYSIS_LOG), exist_ok=True)
    with open(AI_ANALYSIS_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[GATEWAY-LLM] req={req_id} src={src_ip} "
          f"threat={analysis.get('threat_level','?')} "
          f"hyp={analysis.get('attack_hypothesis','?')}")


# -----------------------------------------------------------------------
# FLOW META HEADER — context injected into honeypot request
# -----------------------------------------------------------------------
def build_flow_meta(src_ip, src_port, dst_port, protocol,
                    conn_state, packet_count, flow_duration, ts) -> str:
    counts = _ip_counts[src_ip]
    return json.dumps({
        "src_ip": src_ip, "src_port": src_port,
        "dst_port": dst_port, "protocol": protocol,
        "conn_state": conn_state, "packet_count": packet_count,
        "flow_duration": flow_duration,
        "prior_benign_count":      counts["benign"],
        "prior_suspicious_count":  counts["suspicious"],
        "timestamp": ts,
    }, separators=(",", ":"))


# -----------------------------------------------------------------------
# OLLAMA FALLBACK ANALYSIS
# Called only if beelzebub's LLM response had no <!--ANALYSIS:--> block
# (e.g. Ollama timed out inside the container). Gateway calls Ollama
# directly on localhost as a backup so the record is never blank.
# -----------------------------------------------------------------------
def gateway_llm_analysis(req_id, src_ip, path, flow_meta_str: str) -> dict:
    # Parse flow_meta for richer context
    try:
        flow_meta = json.loads(flow_meta_str)
        prior_suspicious = flow_meta.get("prior_suspicious_count", 0)
        prior_benign     = flow_meta.get("prior_benign_count", 0)
        src_port         = flow_meta.get("src_port", "unknown")
        conn_state       = flow_meta.get("conn_state", "SF")
    except Exception:
        prior_suspicious = 0
        prior_benign     = 0
        src_port         = "unknown"
        conn_state       = "SF"

    # Determine attack hypothesis hints from path
    path_lower = path.lower()
    if any(x in path_lower for x in ["admin", "login", "auth", "panel", "dashboard"]):
        path_hint = "This path targets administrative interfaces — likely recon or credential attack."
    elif any(x in path_lower for x in ["../", "%2e%2e", "passwd", "etc", "proc"]):
        path_hint = "Path contains traversal patterns — likely path_traversal attack."
    elif any(x in path_lower for x in ["select", "union", "drop", "insert", "where", "'"]):
        path_hint = "Path contains SQL keywords — likely sqli attack."
    elif any(x in path_lower for x in ["<script", "alert(", "onerror", "javascript:"]):
        path_hint = "Path contains script tags — likely xss attack."
    elif any(x in path_lower for x in ["cmd", "exec", "shell", "wget", "curl", "bash"]):
        path_hint = "Path contains command keywords — likely rce attempt."
    elif any(x in path_lower for x in ["wp-", "phpmyadmin", "xmlrpc", ".env", ".git"]):
        path_hint = "Path targets known vulnerable endpoints — likely cve_probe."
    else:
        path_hint = "General HTTP probe — likely recon activity."

    prompt = f"""You are a cybersecurity analyst for an IoT honeypot system.
A suspicious HTTP request has been detected and routed to the honeypot.
Analyse it and respond ONLY with a JSON object.

REQUEST DETAILS:
  Source IP      : {src_ip}
  Source Port    : {src_port}
  Requested Path : {path}
  Connection     : {conn_state}
  Prior suspicious requests from this IP : {prior_suspicious}
  Prior benign requests from this IP     : {prior_benign}

PATH ANALYSIS HINT: {path_hint}

RESPOND ONLY WITH THIS JSON — no markdown fences, no prose, no text outside the JSON:
{{
  "req_id": "{req_id}",
  "src_ip": "{src_ip}",
  "why_suspicious": [
    "<specific reason referencing the actual path or IP behaviour>",
    "<second specific reason>"
  ],
  "benign_baseline_comparison": "<one sentence comparing to normal IoT traffic>",
  "attack_hypothesis": "<must be one of: brute_force|path_traversal|cve_probe|recon|sqli|xss|rce|credential_stuffing|unknown>",
  "threat_level": "<must be one of: low|medium|high|critical>",
  "recommended_action": "<specific actionable recommendation>",
  "confidence": <integer between 0 and 100>
}}"""
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "temperature": 0.2,
            },
            timeout=(5, 240),
        )
        resp.raise_for_status()
        raw = resp.json()["choices"][0]["message"]["content"].strip()
        # Strip accidental markdown fences
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        result = json.loads(raw)
        result["analysis_source"] = "gateway_llm"   # gateway's own dedicated analysis call
        return result
        return json.loads(raw)
    except Exception as e:
        print(f"[OLLAMA ERROR] Failed: {e}")
        return {
            "req_id": str(req_id), "src_ip": src_ip,
            "why_suspicious": ["fallback analysis — honeypot LLM produced no block"],
            "benign_baseline_comparison": "unavailable",
            "attack_hypothesis": "unknown",
            "threat_level": "unknown",
            "recommended_action": "Manual review required.",
            "confidence": 0,
            "error": str(e),
        }


# -----------------------------------------------------------------------
# GATEWAY HANDLER
# -----------------------------------------------------------------------
class GatewayHandler(BaseHTTPRequestHandler):

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n > 0 else b""

    def _handle(self, method: str):
        client_ip = self.client_address[0]

        req_id        = int(time.time() * 1000)
        src_ip        = client_ip
        src_port      = self.client_address[1]
        dst_port      = GATEWAY_PORT
        header_bytes = sum(len(k) + len(v) + 4 for k, v in self.headers.items())
        body_bytes   = int(self.headers.get("Content-Length", 0))
        src_bytes    = header_bytes + body_bytes
        flow_duration = 0.001
        packet_count  = 1
        conn_state    = "SF"
        timestamp     = time.time()
        body          = self._read_body()
        path_features = extract_path_features(self.path, body)

        flow = [req_id, src_ip, GATEWAY_IP, src_port, dst_port, 6,
                src_bytes, 0, flow_duration, packet_count, conn_state, timestamp,
                "", "", "", "", "", "", "",   # label (filled in later by hybrid_ai.py) +
                                               # duration/missed_bytes/src_pkts/src_ip_bytes/
                                               # dst_pkts/dst_ip_bytes (gateway never measures these)
                method, path_features["path_length"],
                path_features["has_sql_pattern"], path_features["has_xss_pattern"],
                path_features["has_traversal_pattern"], path_features["has_rce_pattern"],
                path_features["has_recon_cve_pattern"]]

        write_flow(flow)
        try:
            subprocess.run(["python3", AI_SCRIPT], timeout=5)
        except Exception as e:
            print(f"[AI] {e}")
        time.sleep(0.1)

        label = get_label(req_id)
        ai_label = label  # keep the AI's real prediction for logging, separate from routing

        # TESTING OVERRIDE: Attack Sim guarantees honeypot routing for demo
        # purposes, via either the header (server-side spoofed-IP fire) or
        # a query param (real browser navigation can't set custom headers,
        # so this is how the VISIBLE popup tab triggers the same override).
        # Does not affect real traffic (neither present = normal AI routing)
        # and does not change what gets logged as the AI's actual prediction.
        force_suspicious = (
            self.headers.get("X-Force-Suspicious") == "1"
            or parse_qs(urlparse(self.path).query).get("_force_suspicious", ["0"])[0] == "1"
        )
        if force_suspicious:
            label = 1

        # Clean path with the test-only param stripped, so it doesn't leak into
        # analysis narrative or forwarded requests as if a real attacker sent it.
        clean_path = re.sub(r"([?&])_force_suspicious=1&?", r"\1", self.path).rstrip("?&")

        if label == 0:
            _ip_counts[src_ip]["benign"] += 1
            pool = "real"
        else:
            _ip_counts[src_ip]["suspicious"] += 1
            pool = "honeypot"

        target, cluster_idx = next_server(pool)
        log_event(req_id, src_ip, ai_label, target, cluster_idx, pool)

        fwd_headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host","content-length","transfer-encoding","x-force-suspicious")}

        flow_meta_str = ""
        if label == 1:
            flow_meta_str = build_flow_meta(
                src_ip, src_port, dst_port, 6,
                conn_state, packet_count, flow_duration, timestamp
            )
            fwd_headers["X-Gateway-ReqId"]    = str(req_id)
            fwd_headers["X-Gateway-Label"]    = "suspicious"
            fwd_headers["X-Gateway-FlowMeta"] = flow_meta_str

        raw_content = self._forward(method, target, pool, fwd_headers, body)

        if pool == "honeypot":
            print(f"[BEELZEBUB] req={req_id} contacted {target} (container running Beelzebub) "
                  f"- received {len(raw_content)} bytes back")

        content = raw_content
        if label == 1:
            log_line, status, snippet_format = parse_honeypot_snippet(raw_content)
            if log_line is None:
                print(f"[BEELZEBUB] req={req_id} response had no usable content - using generic log line")
                print(f"[DEBUG] req={req_id} raw_content (first 400 chars):\n{raw_content[:400]}")
                log_line, status, snippet_format = "Unusual request pattern detected", "warn", "none"
            else:
                print(f"[BEELZEBUB] req={req_id} LLM-generated content used ({snippet_format}): {log_line!r} ({status})")
            content = render_honeypot_page(log_line, status)
            honeypot_engagement = {
                "source": "honeypot_llm", "log_line": log_line,
                "status": status, "format": snippet_format,
            }

            # Independent of the snippet above - this is the detailed,
            # structured analysis that feeds ai_analysis.log / the dashboard.
            analysis = gateway_llm_analysis(req_id, src_ip, clean_path, flow_meta_str)
            persist_analysis(req_id, src_ip, flow, analysis, honeypot_engagement)

        # Encode response once — used for both writing and dst_bytes measurement
        content_bytes = content.encode("utf-8", errors="replace")

        # Update dst_bytes in CSV with actual response size for better RF training data
        try:
            import csv as _csv
            rows = list(_csv.reader(open(LABELED_CSV)))
            hdr = rows[0]
            di = hdr.index("dst_bytes")
            ri = hdr.index("req_id")
            for row in reversed(rows[1:]):
                if len(row) > ri and row[ri] == str(req_id):
                    row[di] = str(len(content_bytes))
                    break
            with open(LABELED_CSV, "w", newline="") as f:
                _csv.writer(f).writerows(rows)
        except Exception:
            pass  # non-critical

        # Send response — ignore BrokenPipeError (client disconnected mid-response)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content_bytes)
        except BrokenPipeError:
            pass

    def _forward(self, method, target, pool, headers, body) -> str:
        servers = {"real": REAL_SERVERS, "honeypot": HONEYPOT_SERVERS, "dummy": DUMMY_SERVERS}[pool]
        tried   = set()
        for _ in range(len(servers)):
            if target in tried:
                target, _ = next_server(pool)
            tried.add(target)
            try:
                resp = _session.request(
                    method=method,
                    url=target + self.path,
                    headers=headers,
                    data=body or None,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    allow_redirects=False,
                )
                return resp.text
            except requests.exceptions.ConnectionError as e:
                print(f"[LB] Connection failed → {target}: {e}")
                _mark_dead(target)
                target, _ = next_server(pool)
            except requests.exceptions.Timeout as e:
                print(f"[LB] Timeout → {target}: {e}")
                _mark_dead(target)
                target, _ = next_server(pool)
            except Exception as e:
                print(f"[LB] Error → {target}: {e}")
                break
        return ("<html><body><h3>Service temporarily unavailable.</h3>"
                "<p>All backend nodes unreachable — check docker compose ps.</p></body></html>")

    def do_GET(self):  self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_HEAD(self): self._handle("HEAD")
    def log_message(self, fmt, *args): pass


# -----------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------
def main():
    os.makedirs("logs", exist_ok=True)
    startup_checks()
    server = HTTPServer(("0.0.0.0", GATEWAY_PORT), GatewayHandler)
    print(f"[GATEWAY] Listening on 0.0.0.0:{GATEWAY_PORT}")
    server.serve_forever()

if __name__ == "__main__":
    main()
