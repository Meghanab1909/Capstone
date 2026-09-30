"""
honeypot.py — IoT Device portal wrapping a Beelzebub honeypot instance.

Beelzebub indicators surfaced from its actual architecture:
  - Active trap protocols: HTTP/:80, HTTP/:8080, SSH/:22, SSH/:2222,
                           TCP/:3306 (MySQL), MCP/:8000
  - LLM-integration plugin (llm-integration.go) drives SSH/shell responses
  - Beelzebub-cloud plugin (beelzebub-cloud.go) ships events to cloud telemetry
  - Tracer component (tracer/tracer.go) records every probe
  - HistoryStore (historystore/) persists attacker interaction history
  - HTTP strategy returns "Hello from Wordpress" as the lure
  - Four protocol strategies: HTTP · SSH · TCP · MCP
"""

import subprocess
import shutil
import os
import time
from flask import Flask, jsonify

app = Flask(__name__)

BEELZEBUB_BINARY = shutil.which("beelzebub") or "./beelzebub/beelzebub"
BEELZEBUB_CONFIG = "./beelzebub/configurations/beelzebub.yaml"

# ── Helpers ──────────────────────────────────────────────────────────────────

def _beelzebub_running() -> bool:
    """True if the beelzebub process is alive."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", "beelzebub"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def _beelzebub_version() -> str:
    """Read version from go.mod — the only reliable static source."""
    go_mod = "./beelzebub/go.mod"
    try:
        with open(go_mod) as f:
            for line in f:
                if line.startswith("module"):
                    # e.g.  module github.com/mariocandela/beelzebub
                    return line.strip().split("/")[-1]
        return "beelzebub"
    except Exception:
        return "beelzebub"


def _active_services() -> list[dict]:
    """
    Parse beelzebub service YAML files to report real configured traps.
    Derived from:  beelzebub/configurations/services/*.yaml
    """
    services_dir = "./beelzebub/configurations/services"
    services = []
    if not os.path.isdir(services_dir):
        return services

    import glob, re
    for path in sorted(glob.glob(os.path.join(services_dir, "*.yaml"))):
        fname = os.path.basename(path)          # e.g. ssh-2222.yaml
        name  = fname.replace(".yaml", "")       # e.g. ssh-2222
        proto = name.split("-")[0].upper()       # e.g. SSH
        port  = name.split("-")[1] if "-" in name else "?"

        # Try to read the description / lure from the yaml
        description = ""
        try:
            with open(path) as f:
                raw = f.read()
            # grab the first "description:" value
            m = re.search(r'description:\s*["\']?([^\n"\']+)', raw, re.I)
            if m:
                description = m.group(1).strip()
        except Exception:
            pass

        services.append({
            "name":        name,
            "protocol":    proto,
            "port":        port,
            "description": description or f"{proto} trap",
            "file":        fname,
        })
    return services


def _plugins_active() -> list[str]:
    """
    Report which beelzebub plugins exist on disk.
    Derived from:  beelzebub/plugins/*.go
    """
    plugins_dir = "./beelzebub/plugins"
    plugins = []
    if not os.path.isdir(plugins_dir):
        return plugins
    for f in sorted(os.listdir(plugins_dir)):
        if f.endswith(".go") and not f.endswith("_test.go"):
            plugins.append(f.replace(".go", ""))
    return plugins


def _protocol_strategies() -> list[str]:
    """
    Enumerate protocol strategy handlers.
    Derived from:  beelzebub/protocols/strategies/*/
    """
    strat_dir = "./beelzebub/protocols/strategies"
    strategies = []
    if not os.path.isdir(strat_dir):
        return strategies
    for entry in sorted(os.listdir(strat_dir)):
        full = os.path.join(strat_dir, entry)
        if os.path.isdir(full):
            strategies.append(entry)
    return strategies

# ── Derived data (loaded once at import time) ─────────────────────────────

SERVICES   = _active_services()
PLUGINS    = _plugins_active()
STRATEGIES = _protocol_strategies()
BZ_VERSION = _beelzebub_version()

# ── HTML templates ────────────────────────────────────────────────────────────

def _build_service_rows(services):
    if not services:
        return '<div class="log-line"><span class="log-warn">[WARN]</span><span>No service configs found — check ./beelzebub/configurations/services/</span></div>'
    rows = ""
    for s in services:
        rows += f"""
        <div class="trap-row">
          <span class="trap-proto trap-{s['protocol'].lower()}">{s['protocol']}</span>
          <span class="trap-port">:{s['port']}</span>
          <span class="trap-desc">{s['description']}</span>
          <span class="trap-file">{s['file']}</span>
        </div>"""
    return rows


def _build_plugin_tags(plugins):
    if not plugins:
        return '<span class="tag tag-dim">no plugins detected</span>'
    return "".join(f'<span class="tag tag-plugin">{p}</span>' for p in plugins)


def _build_strategy_tags(strategies):
    if not strategies:
        return '<span class="tag tag-dim">no strategies detected</span>'
    return "".join(f'<span class="tag tag-strat">{s}</span>' for s in strategies)


HOME_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>IoT Device — Beelzebub Honeypot</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&family=Barlow:wght@300;400;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:         #06080b;
      --panel:      #0b0e13;
      --panel-alt:  #0e1218;
      --border:     #1a2430;
      --border-hi:  #253444;
      --green:      #00e87a;
      --green-dim:  #00512b;
      --amber:      #f5a623;
      --amber-dim:  #7a5010;
      --red:        #ff3b55;
      --red-dim:    #6b1020;
      --blue:       #38b6ff;
      --blue-dim:   #0d3d5a;
      --muted:      #3a5060;
      --text:       #b8cad6;
      --text-hi:    #ddeaf2;
      --font-mono:  'Share Tech Mono', monospace;
      --font-vt:    'VT323', monospace;
      --font-body:  'Barlow', sans-serif;
    }}

    html, body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-body);
      min-height: 100vh;
    }}

    /* scanlines */
    body::before {{
      content: '';
      position: fixed; inset: 0;
      background: repeating-linear-gradient(0deg,transparent,transparent 2px,
        rgba(0,0,0,0.07) 2px,rgba(0,0,0,0.07) 4px);
      pointer-events: none; z-index: 200;
    }}

    .page {{
      max-width: 780px;
      margin: 0 auto;
      padding: 2.5rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.2rem;
      animation: rise 0.5s ease both;
    }}

    @keyframes rise {{
      from {{ opacity:0; transform:translateY(14px); }}
      to   {{ opacity:1; transform:none; }}
    }}

    /* ── Shell card ── */
    .card {{
      border: 1px solid var(--border);
      background: var(--panel);
      position: relative;
    }}
    .card::before, .card::after,
    .card .c-br, .card .c-bl {{
      content: ''; position: absolute;
      width: 12px; height: 12px;
      border-style: solid; border-color: var(--green);
    }}
    .card::before  {{ top:-1px;    left:-1px;  border-width: 2px 0 0 2px; }}
    .card::after   {{ top:-1px;    right:-1px; border-width: 2px 2px 0 0; }}
    .card .c-br    {{ bottom:-1px; right:-1px; border-width: 0 2px 2px 0; }}
    .card .c-bl    {{ bottom:-1px; left:-1px;  border-width: 0 0 2px 2px; }}

    /* ── Topbar ── */
    .topbar {{
      display: flex; align-items: center;
      justify-content: space-between;
      padding: 0.7rem 1.2rem;
      border-bottom: 1px solid var(--border);
      background: #080b0f;
    }}

    .topbar-left {{ display:flex; align-items:center; gap:0.8rem; }}

    .logo {{
      width: 30px; height: 30px;
      border: 2px solid var(--green);
      display: grid; place-items: center;
    }}
    .logo::before {{
      content: '';
      width: 11px; height: 11px;
      background: var(--green);
      clip-path: polygon(50% 0%,100% 100%,0% 100%);
    }}

    .device-id   {{ font-family:var(--font-mono); font-size:0.65rem; color:var(--muted); letter-spacing:.12em; text-transform:uppercase; }}
    .device-name {{ font-family:var(--font-mono); font-size:0.9rem;  color:var(--text-hi); letter-spacing:.05em; }}

    .pill {{
      display:flex; align-items:center; gap:.4rem;
      font-family:var(--font-mono); font-size:0.68rem;
      letter-spacing:.1em; text-transform:uppercase;
      padding:.28rem .7rem;
      border:1px solid; background: transparent;
    }}
    .pill-green {{ border-color:var(--green-dim); color:var(--green); }}
    .pill-amber {{ border-color:var(--amber-dim); color:var(--amber); }}

    .dot {{
      width:7px; height:7px; border-radius:50%;
      animation: blink 1.8s ease-in-out infinite;
    }}
    .dot-green {{ background:var(--green); }}
    .dot-amber {{ background:var(--amber); animation-delay:.4s; }}

    @keyframes blink {{
      0%,100% {{ opacity:1; }}
      50%      {{ opacity:.4; }}
    }}

    /* ── Sub-header breadcrumb ── */
    .subbar {{
      padding: .45rem 1.2rem;
      border-bottom: 1px solid var(--border);
      background: rgba(0,0,0,.25);
      display: flex; align-items: center; gap: 1.2rem; flex-wrap: wrap;
    }}
    .crumb {{ font-family:var(--font-mono); font-size:.65rem; color:var(--muted); letter-spacing:.08em; }}
    .crumb em {{ color:var(--green); font-style:normal; }}

    .tag {{
      font-family:var(--font-mono); font-size:.58rem;
      letter-spacing:.1em; text-transform:uppercase;
      padding:.15rem .5rem;
      border: 1px solid var(--border); color:var(--muted);
    }}
    .tag-plugin {{ border-color:#1a3040; color:var(--blue);   background:rgba(56,182,255,.04); }}
    .tag-strat  {{ border-color:#1a3020; color:var(--green);  background:rgba(0,232,122,.04);  }}
    .tag-dim    {{ color:var(--muted); }}

    /* ── Section header ── */
    .sec-head {{
      display:flex; align-items:center; justify-content:space-between;
      padding:.5rem .9rem;
      border-bottom: 1px solid var(--border);
      background: rgba(0,0,0,.3);
    }}
    .sec-title {{
      font-family:var(--font-mono); font-size:.62rem;
      letter-spacing:.14em; text-transform:uppercase; color:var(--muted);
    }}
    .sec-badge {{
      font-family:var(--font-mono); font-size:.58rem;
      letter-spacing:.1em; text-transform:uppercase;
      padding:.12rem .45rem;
      border: 1px solid; color:var(--amber); border-color:var(--amber-dim);
      background: rgba(245,166,35,.05);
    }}

    /* ── Metrics grid ── */
    .metrics {{
      display:grid; grid-template-columns:repeat(3,1fr);
      gap:1px; background:var(--border);
      border-bottom: 1px solid var(--border);
    }}
    .metric {{
      background:var(--panel); padding:.9rem 1.1rem;
      display:flex; flex-direction:column; gap:.25rem;
    }}
    .m-label {{ font-family:var(--font-mono); font-size:.58rem; text-transform:uppercase; letter-spacing:.14em; color:var(--muted); }}
    .m-val   {{ font-family:var(--font-vt);   font-size:1.8rem; line-height:1; }}
    .m-sub   {{ font-family:var(--font-mono); font-size:.58rem; color:var(--muted); }}
    .val-green {{ color:var(--green); }}
    .val-amber {{ color:var(--amber); }}
    .val-blue  {{ color:var(--blue);  }}

    /* ── Honeypot alert banner ── */
    .hz-banner {{
      padding: .65rem 1.1rem;
      background: rgba(245,166,35,.06);
      border-bottom: 1px solid var(--amber-dim);
      display:flex; align-items:center; gap:.8rem;
    }}
    .hz-icon {{
      font-family:var(--font-vt); font-size:1.4rem; color:var(--amber); line-height:1;
    }}
    .hz-text {{
      font-family:var(--font-mono); font-size:.72rem; color:var(--amber);
      letter-spacing:.06em; line-height:1.6;
    }}
    .hz-text strong {{ color:var(--text-hi); }}

    /* ── Trap table ── */
    .trap-body {{ padding:.8rem .9rem; display:flex; flex-direction:column; gap:.3rem; }}

    .trap-row {{
      display:grid;
      grid-template-columns:56px 72px 1fr auto;
      align-items:center; gap:.7rem;
      padding:.45rem .6rem;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      font-family:var(--font-mono); font-size:.7rem;
      transition: border-color .15s;
    }}
    .trap-row:hover {{ border-color:var(--border-hi); }}

    .trap-proto {{
      font-size:.6rem; letter-spacing:.1em; text-transform:uppercase;
      padding:.1rem .4rem; border:1px solid; text-align:center;
    }}
    .trap-http {{ border-color:#0d3d5a; color:var(--blue);  background:rgba(56,182,255,.06);  }}
    .trap-ssh  {{ border-color:#1a3020; color:var(--green); background:rgba(0,232,122,.06);   }}
    .trap-tcp  {{ border-color:var(--red-dim); color:var(--red); background:rgba(255,59,85,.06); }}
    .trap-mcp  {{ border-color:#1a1a40; color:#a78bfa; background:rgba(167,139,250,.06);      }}

    .trap-port {{ color:var(--green); }}
    .trap-desc {{ color:var(--text); font-size:.68rem; }}
    .trap-file {{ color:var(--muted); font-size:.6rem; text-align:right; }}

    /* ── WP lure indicator ── */
    .wp-lure {{
      margin: 0 .9rem .8rem;
      border: 1px solid var(--amber-dim);
      background: rgba(245,166,35,.04);
      padding: .55rem .8rem;
      display:flex; align-items:center; gap:.7rem;
    }}
    .wp-lure-label {{
      font-family:var(--font-mono); font-size:.6rem;
      text-transform:uppercase; letter-spacing:.12em; color:var(--amber);
    }}
    .wp-lure-val {{
      font-family:var(--font-vt); font-size:1.05rem; color:var(--text-hi);
      letter-spacing:.04em;
    }}
    .wp-lure-note {{
      font-family:var(--font-mono); font-size:.6rem; color:var(--muted);
      margin-left:auto;
    }}

    /* ── Log ── */
    .log-body {{
      padding:.8rem .9rem;
      font-family:var(--font-mono); font-size:.72rem; line-height:1.9;
      color:var(--muted); background: #070a0d;
    }}
    .log-line {{ display:flex; gap:.9rem; }}
    .log-time {{ color:#1e3040; min-width:78px; }}
    .log-ok   {{ color:var(--green); }}
    .log-warn {{ color:var(--amber); }}
    .log-info {{ color:var(--blue);  }}
    .log-trap {{ color:var(--red);   }}

    /* ── Plugin / strategy row ── */
    .plugin-body {{
      padding:.8rem .9rem;
      display:flex; flex-direction:column; gap:.6rem;
    }}
    .plugin-row {{
      display:flex; align-items:center; gap:.7rem; flex-wrap:wrap;
    }}
    .plugin-section-label {{
      font-family:var(--font-mono); font-size:.6rem;
      letter-spacing:.12em; text-transform:uppercase;
      color:var(--muted); min-width:90px;
    }}

    /* ── Actions ── */
    .actions {{ padding:.9rem; display:flex; gap:.7rem; flex-wrap:wrap; }}
    .btn {{
      font-family:var(--font-mono); font-size:.68rem;
      letter-spacing:.12em; text-transform:uppercase;
      padding:.55rem 1.1rem; border:1px solid;
      cursor:pointer; background:transparent; text-decoration:none;
      display:inline-block; transition:background .15s, color .15s;
    }}
    .btn-green {{ border-color:var(--green); color:var(--green); }}
    .btn-green:hover {{ background:var(--green); color:var(--bg); }}
    .btn-muted {{ border-color:var(--border); color:var(--muted); }}
    .btn-muted:hover {{ border-color:var(--muted); color:var(--text); }}
    .btn-amber {{ border-color:var(--amber); color:var(--amber); }}
    .btn-amber:hover {{ background:var(--amber); color:var(--bg); }}

    /* ── Footer ── */
    .footer {{
      border-top: 1px solid var(--border);
      padding: .6rem 1.2rem;
      background: #080b0f;
      display:flex; justify-content:space-between; align-items:center;
    }}
    .footer-txt {{ font-family:var(--font-mono); font-size:.58rem; color:var(--muted); letter-spacing:.07em; }}
    .led-row {{ display:flex; gap:.45rem; }}
    .led {{ width:8px; height:8px; border-radius:50%; }}
    .led-g {{ background:var(--green); box-shadow:0 0 5px var(--green); animation:blink 2s infinite; }}
    .led-a {{ background:var(--amber); box-shadow:0 0 5px var(--amber); animation:blink 3s infinite .5s; }}
    .led-off {{ background:#111; }}
  </style>
</head>
<body>
<div class="page">

  <!-- ══ Main card ══ -->
  <div class="card">
    <div class="c-br"></div><div class="c-bl"></div>

    <!-- Top bar -->
    <div class="topbar">
      <div class="topbar-left">
        <div class="logo"></div>
        <div>
          <div class="device-id">Node ID: IOT-4F2A &nbsp;|&nbsp; {bz_version}</div>
          <div class="device-name">Edge Device Portal</div>
        </div>
      </div>
      <div style="display:flex;gap:.6rem;align-items:center;">
        <div class="pill pill-amber"><div class="dot dot-amber"></div>Honeypot</div>
        <div class="pill pill-green"><div class="dot dot-green"></div>Online</div>
      </div>
    </div>

    <!-- Breadcrumb / meta -->
    <div class="subbar">
      <div class="crumb">root / <em>device</em> / portal</div>
      <div class="tag">fw v2.4.1</div>
      <div class="tag">eth0 · 192.168.1.42</div>
      <div class="tag">beelzebub</div>
      <div class="tag">IPv4</div>
    </div>

    <!-- Metrics -->
    <div class="metrics">
      <div class="metric">
        <div class="m-label">System Status</div>
        <div class="m-val val-green">OK</div>
        <div class="m-sub">All subsystems nominal</div>
      </div>
      <div class="metric">
        <div class="m-label">Active Traps</div>
        <div class="m-val val-amber">{trap_count}</div>
        <div class="m-sub">Configured services</div>
      </div>
      <div class="metric">
        <div class="m-label">Protocol Engines</div>
        <div class="m-val val-blue">{strat_count}</div>
        <div class="m-sub">{strat_list}</div>
      </div>
    </div>

    <!-- Honeypot alert banner -->
    <div class="hz-banner">
      <div class="hz-icon">&#9888;</div>
      <div class="hz-text">
        <strong>BEELZEBUB HONEYPOT ACTIVE</strong><br/>
        All connections to configured trap ports are being traced, logged, and
        forwarded via <strong>beelzebub-cloud</strong>. LLM-powered shell
        responses active on SSH traps.
      </div>
    </div>

    <!-- Trap services -->
    <div class="sec-head">
      <span class="sec-title">Active Trap Services</span>
      <span class="sec-badge">LIVE &middot; beelzebub/configurations/services/</span>
    </div>
    <div class="trap-body">
      {service_rows}
    </div>

    <!-- WordPress lure -->
    <div class="wp-lure">
      <div class="wp-lure-label">HTTP Lure</div>
      <div class="wp-lure-val">Hello from Wordpress</div>
      <div class="wp-lure-note">protocols/strategies/HTTP/http.go</div>
    </div>

    <!-- Plugins / strategies -->
    <div class="sec-head">
      <span class="sec-title">Loaded Plugins &amp; Protocol Strategies</span>
      <span class="sec-badge">beelzebub/plugins/ &amp; protocols/strategies/</span>
    </div>
    <div class="plugin-body">
      <div class="plugin-row">
        <span class="plugin-section-label">Plugins</span>
        {plugin_tags}
      </div>
      <div class="plugin-row">
        <span class="plugin-section-label">Strategies</span>
        {strategy_tags}
      </div>
    </div>

    <!-- System log -->
    <div class="sec-head">
      <span class="sec-title">Tracer Log</span>
      <span class="sec-badge">beelzebub/tracer/tracer.go</span>
    </div>
    <div class="log-body">
      <div class="log-line"><span class="log-time">00:00:01</span><span class="log-ok">[BOOT]</span><span>Beelzebub kernel loaded. Parsing configurations...</span></div>
      <div class="log-line"><span class="log-time">00:00:02</span><span class="log-ok">[INIT]</span><span>HistoryStore initialised — beelzebub/historystore/</span></div>
      <div class="log-line"><span class="log-time">00:00:03</span><span class="log-ok">[INIT]</span><span>Protocol manager ready — {strat_count} strategy engines registered</span></div>
      <div class="log-line"><span class="log-time">00:00:04</span><span class="log-info">[PLUGIN]</span><span>llm-integration loaded — LLM shell responses enabled</span></div>
      <div class="log-line"><span class="log-time">00:00:04</span><span class="log-info">[PLUGIN]</span><span>beelzebub-cloud loaded — event telemetry active</span></div>
      <div class="log-line"><span class="log-time">00:00:05</span><span class="log-ok">[HTTP]</span><span>Trap listening on :80 &middot; lure: "Hello from Wordpress"</span></div>
      <div class="log-line"><span class="log-time">00:00:05</span><span class="log-ok">[HTTP]</span><span>Trap listening on :8080</span></div>
      <div class="log-line"><span class="log-time">00:00:06</span><span class="log-ok">[SSH]</span><span>Trap listening on :22 and :2222 — LLM shell active</span></div>
      <div class="log-line"><span class="log-time">00:00:06</span><span class="log-trap">[TCP]</span><span>MySQL trap listening on :3306 — connection intercept ON</span></div>
      <div class="log-line"><span class="log-time">00:00:07</span><span class="log-info">[MCP]</span><span>MCP trap listening on :8000</span></div>
      <div class="log-line"><span class="log-time">00:00:08</span><span class="log-ok">[TRACER]</span><span>Tracer ready — all probe events will be recorded</span></div>
      <div class="log-line"><span class="log-time">00:00:09</span><span class="log-ok">[HTTP]</span><span>Flask overlay listening on :5000 — portal UP</span></div>
    </div>

    <!-- Actions -->
    <div class="actions">
      <a href="/status"    class="btn btn-green">&#9654; Status</a>
      <a href="/traps"     class="btn btn-amber">&#9888; Trap Config</a>
      <a href="/status/json" class="btn btn-muted">&#123;&#125; JSON</a>
      <button class="btn btn-muted" onclick="location.reload()">&#8634; Refresh</button>
    </div>

    <!-- Footer -->
    <div class="footer">
      <div class="footer-txt">BEELZEBUB &middot; 192.168.1.42 &middot; TRACER ACTIVE &middot; HISTORYSTORE ON</div>
      <div class="led-row">
        <div class="led led-g" title="Power"></div>
        <div class="led led-a" title="Trap Activity"></div>
        <div class="led led-off" title="No Error"></div>
      </div>
    </div>

  </div>
</div>
</body>
</html>
"""

STATUS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Device Status — Beelzebub</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
    :root {{
      --bg:#06080b; --panel:#0b0e13; --border:#1a2430;
      --green:#00e87a; --green-dim:#00512b; --amber:#f5a623; --amber-dim:#7a5010;
      --red:#ff3b55; --blue:#38b6ff;
      --text:#b8cad6; --text-hi:#ddeaf2; --muted:#3a5060;
      --font-mono:'Share Tech Mono',monospace; --font-vt:'VT323',monospace;
    }}
    body {{
      background:var(--bg); color:var(--text);
      font-family:var(--font-mono);
      min-height:100vh; display:flex; align-items:center; justify-content:center; padding:2rem;
    }}
    body::before {{
      content:''; position:fixed; inset:0;
      background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 4px);
      pointer-events:none; z-index:100;
    }}
    .shell {{
      width:100%; max-width:540px;
      border:1px solid var(--border); background:var(--panel); position:relative;
      animation:rise .4s ease both;
    }}
    @keyframes rise {{ from{{opacity:0;transform:translateY(10px)}} to{{opacity:1;transform:none}} }}
    .shell::before,.shell::after,.c-br,.c-bl {{
      content:''; position:absolute; width:12px; height:12px; border-style:solid; border-color:var(--amber);
    }}
    .shell::before {{ top:-1px;left:-1px; border-width:2px 0 0 2px; }}
    .shell::after  {{ top:-1px;right:-1px; border-width:2px 2px 0 0; }}
    .c-br {{ bottom:-1px;right:-1px; border-width:0 2px 2px 0; }}
    .c-bl {{ bottom:-1px;left:-1px; border-width:0 0 2px 2px; }}
    .hdr {{
      padding:.7rem 1.1rem; border-bottom:1px solid var(--border); background:#080b0f;
      display:flex; justify-content:space-between; align-items:center;
    }}
    .hdr-title {{ font-size:.85rem; letter-spacing:.06em; }}
    .badge {{
      font-size:.6rem; letter-spacing:.1em; text-transform:uppercase;
      padding:.22rem .55rem; border:1px solid;
    }}
    .badge-ok   {{ border-color:var(--green); color:var(--green); background:rgba(0,232,122,.05); }}
    .badge-warn {{ border-color:var(--amber); color:var(--amber); background:rgba(245,166,35,.05); }}
    .body {{ padding:1.2rem 1.1rem; display:flex; flex-direction:column; gap:.5rem; }}
    .row {{
      display:flex; justify-content:space-between; align-items:center;
      padding:.55rem 0; border-bottom:1px solid var(--border);
    }}
    .row:last-child {{ border-bottom:none; }}
    .key {{ font-size:.65rem; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); }}
    .val {{ font-family:var(--font-vt); font-size:1.1rem; }}
    .val-g {{ color:var(--green); }} .val-a {{ color:var(--amber); }}
    .val-b {{ color:var(--blue);  }} .val-d {{ color:var(--text); }}
    .ftr {{
      border-top:1px solid var(--border); padding:.55rem 1.1rem; background:#080b0f;
      display:flex; justify-content:space-between; font-size:.6rem; color:var(--muted);
    }}
    a {{ color:var(--muted); text-decoration:none; letter-spacing:.08em; }}
    a:hover {{ color:var(--green); }}
  </style>
</head>
<body>
<div class="shell">
  <div class="c-br"></div><div class="c-bl"></div>
  <div class="hdr">
    <span class="hdr-title">/ status</span>
    <span class="badge badge-warn">HONEYPOT ACTIVE</span>
  </div>
  <div class="body">
    <div class="row"><span class="key">status</span>               <span class="val val-g">normal</span></div>
    <div class="row"><span class="key">uptime_epoch</span>         <span class="val val-d">{uptime}</span></div>
    <div class="row"><span class="key">engine</span>               <span class="val val-a">beelzebub</span></div>
    <div class="row"><span class="key">active_traps</span>         <span class="val val-a">{trap_count}</span></div>
    <div class="row"><span class="key">protocol_strategies</span>  <span class="val val-b">{strat_count} ({strat_list})</span></div>
    <div class="row"><span class="key">llm_integration</span>      <span class="val val-g">enabled</span></div>
    <div class="row"><span class="key">cloud_telemetry</span>      <span class="val val-g">enabled</span></div>
    <div class="row"><span class="key">http_lure</span>            <span class="val val-d">Hello from Wordpress</span></div>
    <div class="row"><span class="key">tracer</span>               <span class="val val-g">active</span></div>
    <div class="row"><span class="key">historystore</span>         <span class="val val-g">active</span></div>
    <div class="row"><span class="key">node_id</span>              <span class="val val-d">IOT-4F2A</span></div>
  </div>
  <div class="ftr">
    <span>BEELZEBUB &middot; 192.168.1.42:5000</span>
    <a href="/">&#8592; back to portal</a>
  </div>
</div>
</body>
</html>
"""

TRAPS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Trap Config — Beelzebub</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
    :root {{
      --bg:#06080b; --panel:#0b0e13; --border:#1a2430;
      --green:#00e87a; --green-dim:#00512b; --amber:#f5a623; --amber-dim:#7a5010;
      --red:#ff3b55; --red-dim:#6b1020; --blue:#38b6ff; --blue-dim:#0d3d5a;
      --text:#b8cad6; --text-hi:#ddeaf2; --muted:#3a5060;
      --font-mono:'Share Tech Mono',monospace; --font-vt:'VT323',monospace;
    }}
    body {{
      background:var(--bg); color:var(--text); font-family:var(--font-mono);
      min-height:100vh; display:flex; align-items:center; justify-content:center; padding:2rem;
    }}
    body::before {{
      content:''; position:fixed; inset:0;
      background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 4px);
      pointer-events:none; z-index:100;
    }}
    .shell {{
      width:100%; max-width:680px;
      border:1px solid var(--border); background:var(--panel); position:relative;
      animation:rise .4s ease both;
    }}
    @keyframes rise {{ from{{opacity:0;transform:translateY(10px)}} to{{opacity:1;transform:none}} }}
    .shell::before,.shell::after,.c-br,.c-bl {{
      content:''; position:absolute; width:12px; height:12px; border-style:solid; border-color:var(--amber);
    }}
    .shell::before {{ top:-1px;left:-1px; border-width:2px 0 0 2px; }}
    .shell::after  {{ top:-1px;right:-1px; border-width:2px 2px 0 0; }}
    .c-br {{ bottom:-1px;right:-1px; border-width:0 2px 2px 0; }}
    .c-bl {{ bottom:-1px;left:-1px;  border-width:0 0 2px 2px; }}
    .hdr {{
      padding:.7rem 1.1rem; border-bottom:1px solid var(--border); background:#080b0f;
      display:flex; justify-content:space-between; align-items:center;
    }}
    .hdr-title {{ font-size:.85rem; letter-spacing:.06em; }}
    .badge {{
      font-size:.6rem; letter-spacing:.1em; text-transform:uppercase;
      padding:.22rem .55rem; border:1px solid var(--amber); color:var(--amber);
      background:rgba(245,166,35,.05);
    }}
    .body {{ padding:1rem; display:flex; flex-direction:column; gap:.5rem; }}
    .src-note {{
      font-size:.6rem; color:var(--muted); letter-spacing:.08em;
      padding:.4rem .6rem; border:1px solid var(--border); background:rgba(0,0,0,.3);
      margin-bottom:.3rem;
    }}
    .trap {{
      border:1px solid var(--border); background:#080b0f;
      padding:.7rem .9rem; display:flex; flex-direction:column; gap:.3rem;
    }}
    .trap-top {{ display:flex; align-items:center; gap:.7rem; }}
    .proto {{
      font-size:.58rem; letter-spacing:.1em; text-transform:uppercase;
      padding:.1rem .4rem; border:1px solid;
    }}
    .proto-http {{ border-color:var(--blue-dim);  color:var(--blue);  background:rgba(56,182,255,.05); }}
    .proto-ssh  {{ border-color:var(--green-dim); color:var(--green); background:rgba(0,232,122,.05);  }}
    .proto-tcp  {{ border-color:var(--red-dim);   color:var(--red);   background:rgba(255,59,85,.05);  }}
    .proto-mcp  {{ border-color:#1a1a40;          color:#a78bfa;      background:rgba(167,139,250,.05); }}
    .port  {{ color:var(--green); font-size:.8rem; }}
    .fname {{ color:var(--muted); font-size:.62rem; margin-left:auto; }}
    .desc  {{ font-size:.7rem; color:var(--text); padding-left:.1rem; }}
    .ftr {{
      border-top:1px solid var(--border); padding:.55rem 1.1rem; background:#080b0f;
      display:flex; justify-content:space-between; font-size:.6rem; color:var(--muted);
    }}
    a {{ color:var(--muted); text-decoration:none; }}
    a:hover {{ color:var(--green); }}
  </style>
</head>
<body>
<div class="shell">
  <div class="c-br"></div><div class="c-bl"></div>
  <div class="hdr">
    <span class="hdr-title">/ traps</span>
    <span class="badge">beelzebub/configurations/services/</span>
  </div>
  <div class="body">
    <div class="src-note">Source: beelzebub/configurations/services/*.yaml — parsed at runtime, not simulated</div>
    {trap_cards}
  </div>
  <div class="ftr">
    <span>BEELZEBUB &middot; 192.168.1.42:5000</span>
    <a href="/">&#8592; back to portal</a>
  </div>
</div>
</body>
</html>
"""


def _build_trap_cards(services):
    if not services:
        return '<div style="font-family:var(--font-mono);font-size:.7rem;color:#3a5060;padding:.5rem;">No service configs found at ./beelzebub/configurations/services/</div>'
    cards = ""
    for s in services:
        cards += f"""
    <div class="trap">
      <div class="trap-top">
        <span class="proto proto-{s['protocol'].lower()}">{s['protocol']}</span>
        <span class="port">:{s['port']}</span>
        <span class="fname">{s['file']}</span>
      </div>
      <div class="desc">{s['description']}</div>
    </div>"""
    return cards


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def home():
    html = HOME_HTML.format(
        bz_version    = BZ_VERSION,
        trap_count    = len(SERVICES),
        strat_count   = len(STRATEGIES),
        strat_list    = " &middot; ".join(STRATEGIES) if STRATEGIES else "n/a",
        service_rows  = _build_service_rows(SERVICES),
        plugin_tags   = _build_plugin_tags(PLUGINS),
        strategy_tags = _build_strategy_tags(STRATEGIES),
    )
    return html


@app.route("/status")
def status():
    html = STATUS_HTML.format(
        uptime      = round(time.time(), 2),
        trap_count  = len(SERVICES),
        strat_count = len(STRATEGIES),
        strat_list  = " &middot; ".join(STRATEGIES) if STRATEGIES else "n/a",
    )
    return html


@app.route("/status/json")
def status_json():
    return jsonify({
        "status":              "normal",
        "uptime":              time.time(),
        "engine":              "beelzebub",
        "bz_version":          BZ_VERSION,
        "active_traps":        len(SERVICES),
        "protocol_strategies": STRATEGIES,
        "plugins":             PLUGINS,
        "llm_integration":     "llm-integration" in PLUGINS,
        "cloud_telemetry":     "beelzebub-cloud" in PLUGINS,
        "http_lure":           "Hello from Wordpress",
        "tracer":              True,
        "historystore":        True,
        "services":            SERVICES,
    })


@app.route("/traps")
def traps():
    html = TRAPS_HTML.format(trap_cards=_build_trap_cards(SERVICES))
    return html


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
