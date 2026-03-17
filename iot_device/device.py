from flask import Flask
import time

app = Flask(__name__)

HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>IoT Device Portal</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:        #0a0c0f;
      --panel:     #0f1318;
      --border:    #1e2730;
      --green:     #00e87a;
      --green-dim: #00643a;
      --amber:     #f5a623;
      --red:       #ff3b55;
      --text:      #c8d6e0;
      --muted:     #4a606e;
      --font-mono: 'Share Tech Mono', monospace;
      --font-body: 'Barlow', sans-serif;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-body);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      overflow-x: hidden;
    }

    /* Scanline overlay */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.08) 2px,
        rgba(0,0,0,0.08) 4px
      );
      pointer-events: none;
      z-index: 100;
    }

    /* Noise texture */
    body::after {
      content: '';
      position: fixed;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
      opacity: 0.4;
      pointer-events: none;
      z-index: 99;
    }

    .shell {
      width: 100%;
      max-width: 680px;
      border: 1px solid var(--border);
      background: var(--panel);
      position: relative;
      animation: fadeIn 0.6s ease both;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(12px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    /* Corner marks */
    .shell::before, .shell::after,
    .corner-br, .corner-bl {
      content: '';
      position: absolute;
      width: 14px;
      height: 14px;
      border-color: var(--green);
      border-style: solid;
    }
    .shell::before { top: -1px; left: -1px; border-width: 2px 0 0 2px; }
    .shell::after  { top: -1px; right: -1px; border-width: 2px 2px 0 0; }
    .corner-br { bottom: -1px; right: -1px; border-width: 0 2px 2px 0; }
    .corner-bl { bottom: -1px; left: -1px;  border-width: 0 0 2px 2px; }

    /* ── Header bar ── */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem 1.4rem;
      border-bottom: 1px solid var(--border);
      background: #0b0e13;
    }

    .header-left {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .logo-mark {
      width: 28px;
      height: 28px;
      border: 2px solid var(--green);
      display: grid;
      place-items: center;
      position: relative;
    }
    .logo-mark::before {
      content: '';
      width: 10px;
      height: 10px;
      background: var(--green);
      clip-path: polygon(50% 0%, 100% 100%, 0% 100%);
    }

    .device-label {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      color: var(--muted);
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }
    .device-name {
      font-family: var(--font-mono);
      font-size: 0.95rem;
      color: var(--text);
      letter-spacing: 0.06em;
    }

    .status-pill {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--green);
      border: 1px solid var(--green-dim);
      padding: 0.3rem 0.75rem;
      background: rgba(0,232,122,0.05);
    }

    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
      animation: pulse 1.8s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0,232,122,0.6); }
      50%       { opacity: 0.6; box-shadow: 0 0 0 5px rgba(0,232,122,0); }
    }

    /* ── Sub-header ── */
    .sub-header {
      padding: 0.5rem 1.4rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 1.5rem;
      background: rgba(0,0,0,0.2);
    }

    .breadcrumb {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      color: var(--muted);
      letter-spacing: 0.08em;
    }
    .breadcrumb span { color: var(--green); }

    .tag {
      font-family: var(--font-mono);
      font-size: 0.62rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      padding: 0.15rem 0.5rem;
      border: 1px solid var(--border);
      color: var(--muted);
    }

    /* ── Main content ── */
    .content {
      padding: 2rem 1.4rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    /* ── Metrics row ── */
    .metrics {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
    }

    .metric {
      background: var(--panel);
      padding: 1rem 1.2rem;
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
      animation: fadeIn 0.6s ease both;
    }
    .metric:nth-child(1) { animation-delay: 0.1s; }
    .metric:nth-child(2) { animation-delay: 0.2s; }
    .metric:nth-child(3) { animation-delay: 0.3s; }

    .metric-label {
      font-family: var(--font-mono);
      font-size: 0.6rem;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      color: var(--muted);
    }

    .metric-value {
      font-family: var(--font-mono);
      font-size: 1.5rem;
      color: var(--green);
      line-height: 1;
    }

    .metric-sub {
      font-family: var(--font-mono);
      font-size: 0.62rem;
      color: var(--muted);
    }

    /* ── Terminal log ── */
    .log-block {
      border: 1px solid var(--border);
      background: #080b0e;
    }

    .log-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.5rem 0.9rem;
      border-bottom: 1px solid var(--border);
      background: rgba(0,0,0,0.3);
    }

    .log-title {
      font-family: var(--font-mono);
      font-size: 0.65rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
    }

    .log-body {
      padding: 0.9rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      line-height: 1.9;
      color: #4a606e;
    }

    .log-line { display: flex; gap: 1rem; }
    .log-time { color: #2a404e; min-width: 80px; }
    .log-ok   { color: var(--green); }
    .log-warn { color: var(--amber); }
    .log-info { color: #4a8fa8; }

    /* ── Actions ── */
    .actions {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }

    .btn {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      padding: 0.6rem 1.2rem;
      border: 1px solid;
      cursor: pointer;
      background: transparent;
      transition: background 0.15s, color 0.15s;
      text-decoration: none;
      display: inline-block;
    }

    .btn-primary {
      border-color: var(--green);
      color: var(--green);
    }
    .btn-primary:hover {
      background: var(--green);
      color: var(--bg);
    }

    .btn-secondary {
      border-color: var(--border);
      color: var(--muted);
    }
    .btn-secondary:hover {
      border-color: var(--muted);
      color: var(--text);
    }

    .btn-danger {
      border-color: var(--red);
      color: var(--red);
    }
    .btn-danger:hover {
      background: var(--red);
      color: #fff;
    }

    /* ── Footer ── */
    .footer {
      border-top: 1px solid var(--border);
      padding: 0.65rem 1.4rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #0b0e13;
    }

    .footer-left {
      font-family: var(--font-mono);
      font-size: 0.62rem;
      color: var(--muted);
      letter-spacing: 0.08em;
    }

    .led-row {
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }

    .led {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }
    .led-green  { background: var(--green); box-shadow: 0 0 5px var(--green); animation: pulse 2s infinite; }
    .led-amber  { background: var(--amber); box-shadow: 0 0 5px var(--amber); animation: pulse 3s infinite 0.5s; }
    .led-red    { background: #1a1a1a; }

    /* ── Divider ── */
    .divider {
      border: none;
      border-top: 1px solid var(--border);
    }
  </style>
</head>
<body>

<div class="shell">
  <div class="corner-br"></div>
  <div class="corner-bl"></div>

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="logo-mark"></div>
      <div>
        <div class="device-label">Node ID: IOT-4F2A</div>
        <div class="device-name">Edge Device Portal</div>
      </div>
    </div>
    <div class="status-pill">
      <div class="pulse-dot"></div>
      Online
    </div>
  </div>

  <!-- Sub-header -->
  <div class="sub-header">
    <div class="breadcrumb">root / <span>device</span> / status</div>
    <div class="tag">fw v2.4.1</div>
    <div class="tag">eth0</div>
    <div class="tag">IPv4</div>
  </div>

  <!-- Content -->
  <div class="content">

    <!-- Metrics -->
    <div class="metrics">
      <div class="metric">
        <div class="metric-label">System Status</div>
        <div class="metric-value">OK</div>
        <div class="metric-sub">All subsystems nominal</div>
      </div>
      <div class="metric">
        <div class="metric-label">Signal Strength</div>
        <div class="metric-value">&#8211;62</div>
        <div class="metric-sub">dBm &nbsp;&#x2022;&nbsp; RSSI Good</div>
      </div>
      <div class="metric">
        <div class="metric-label">CPU Temp</div>
        <div class="metric-value">41&deg;</div>
        <div class="metric-sub">Celsius &nbsp;&#x2022;&nbsp; Normal</div>
      </div>
    </div>

    <!-- Log -->
    <div class="log-block">
      <div class="log-header">
        <span class="log-title">System Log</span>
        <span class="log-title">live</span>
      </div>
      <div class="log-body">
        <div class="log-line"><span class="log-time">00:00:01</span><span class="log-ok">[BOOT]</span><span>Kernel loaded. Mounting filesystems...</span></div>
        <div class="log-line"><span class="log-time">00:00:03</span><span class="log-ok">[INIT]</span><span>Network interface eth0 UP</span></div>
        <div class="log-line"><span class="log-time">00:00:04</span><span class="log-info">[DHCP]</span><span>Address acquired: 192.168.1.42</span></div>
        <div class="log-line"><span class="log-time">00:00:06</span><span class="log-ok">[MQTT]</span><span>Broker connected — topic: /dev/iot-4f2a</span></div>
        <div class="log-line"><span class="log-time">00:00:08</span><span class="log-warn">[SENSOR]</span><span>Humidity probe: calibration drift +1.2%</span></div>
        <div class="log-line"><span class="log-time">00:00:09</span><span class="log-ok">[HTTP]</span><span>Flask server listening on 0.0.0.0:5000</span></div>
      </div>
    </div>

    <!-- Actions -->
    <div class="actions">
      <a href="/status" class="btn btn-primary">&#x25B6; Status JSON</a>
      <button class="btn btn-secondary" onclick="location.reload()">&#x21BA; Refresh</button>
      <button class="btn btn-danger">&#x23F9; Reboot</button>
    </div>

  </div>

  <!-- Footer -->
  <div class="footer">
    <div class="footer-left">SYS &#x2022; 192.168.1.42:5000 &#x2022; UPTIME ACTIVE</div>
    <div class="led-row">
      <div class="led led-green" title="Power"></div>
      <div class="led led-amber" title="Activity"></div>
      <div class="led led-red"   title="Error"></div>
    </div>
  </div>

</div>

</body>
</html>
"""

STATUS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Device Status</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0a0c0f; --panel: #0f1318; --border: #1e2730;
      --green: #00e87a; --green-dim: #00643a; --amber: #f5a623;
      --text: #c8d6e0; --muted: #4a606e;
      --font-mono: 'Share Tech Mono', monospace;
      --font-body: 'Barlow', sans-serif;
    }
    body {
      background: var(--bg); color: var(--text);
      font-family: var(--font-body);
      min-height: 100vh; display: flex;
      align-items: center; justify-content: center; padding: 2rem;
    }
    body::before {
      content: ''; position: fixed; inset: 0;
      background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.08) 2px,rgba(0,0,0,0.08) 4px);
      pointer-events: none; z-index: 100;
    }
    .shell {
      width: 100%; max-width: 520px;
      border: 1px solid var(--border);
      background: var(--panel); position: relative;
      animation: fadeIn 0.5s ease both;
    }
    @keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:none} }
    .shell::before,.shell::after,.corner-br,.corner-bl {
      content:''; position:absolute; width:12px; height:12px;
      border-color:var(--green); border-style:solid;
    }
    .shell::before { top:-1px;left:-1px; border-width:2px 0 0 2px; }
    .shell::after  { top:-1px;right:-1px; border-width:2px 2px 0 0; }
    .corner-br { bottom:-1px;right:-1px; border-width:0 2px 2px 0; }
    .corner-bl { bottom:-1px;left:-1px;  border-width:0 0 2px 2px; }
    .header {
      padding: 0.75rem 1.2rem; border-bottom: 1px solid var(--border);
      background: #0b0e13; display:flex; justify-content:space-between; align-items:center;
    }
    .title { font-family:var(--font-mono); font-size:0.85rem; letter-spacing:0.08em; }
    .badge {
      font-family:var(--font-mono); font-size:0.62rem; letter-spacing:0.1em;
      text-transform:uppercase; padding:0.25rem 0.6rem;
      border:1px solid var(--green-dim); color:var(--green);
      background:rgba(0,232,122,0.05);
    }
    .body { padding: 1.4rem 1.2rem; display:flex; flex-direction:column; gap:0.6rem; }
    .row {
      display:flex; justify-content:space-between; align-items:center;
      padding:0.6rem 0; border-bottom:1px solid var(--border);
    }
    .row:last-child { border-bottom:none; }
    .key { font-family:var(--font-mono); font-size:0.68rem; letter-spacing:0.1em; text-transform:uppercase; color:var(--muted); }
    .val { font-family:var(--font-mono); font-size:0.82rem; color:var(--green); }
    .val-dim { color:var(--text); }
    .footer {
      border-top:1px solid var(--border); padding:0.6rem 1.2rem;
      background:#0b0e13;
      font-family:var(--font-mono); font-size:0.6rem; color:var(--muted);
      display:flex; justify-content:space-between;
    }
    .back { text-decoration:none; color:var(--muted); font-family:var(--font-mono); font-size:0.65rem; letter-spacing:0.1em; transition:color 0.15s; }
    .back:hover { color:var(--green); }
  </style>
</head>
<body>
<div class="shell">
  <div class="corner-br"></div><div class="corner-bl"></div>
  <div class="header">
    <span class="title">/ status</span>
    <span class="badge">200 OK</span>
  </div>
  <div class="body">
    <div class="row">
      <span class="key">status</span>
      <span class="val">normal</span>
    </div>
    <div class="row">
      <span class="key">uptime</span>
      <span class="val val-dim">{{ uptime }}</span>
    </div>
    <div class="row">
      <span class="key">node_id</span>
      <span class="val val-dim">IOT-4F2A</span>
    </div>
    <div class="row">
      <span class="key">endpoint</span>
      <span class="val val-dim">/status</span>
    </div>
    <div class="row">
      <span class="key">content-type</span>
      <span class="val val-dim">text/html</span>
    </div>
  </div>
  <div class="footer">
    <span>SYS &#x2022; 192.168.1.42:5000</span>
    <a href="/" class="back">&#x2190; back to portal</a>
  </div>
</div>
</body>
</html>
"""

app = Flask(__name__)

@app.route("/")
def home():
    return HOME_HTML

@app.route("/status")
def status():
    uptime = round(time.time(), 2)
    page = STATUS_HTML.replace("{{ uptime }}", str(uptime))
    return page

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
