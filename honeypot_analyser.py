#!/usr/bin/env python3
"""
honeypot_analyser.py
Reads logs/beelzebub/beelzebub.log, groups events into sessions,
sends each session to Ollama (llama3:8b) for threat analysis,
writes structured report to logs/honeypot_report.json

Can also be imported and called per-session from app.py.
"""

import json
import os
import re
import requests
from datetime import datetime, timezone
from collections import defaultdict

LOG_PATH    = "logs/beelzebub/beelzebub.log"
REPORT_PATH = "logs/honeypot_report.json"
OLLAMA_URL  = "http://127.0.0.1:11434/api/chat"
MODEL       = "llama3:8b"

# ── Parse log file ─────────────────────────────────────────────
def parse_log():
    if not os.path.exists(LOG_PATH):
        return []
    events = []
    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "event" in obj:
                    events.append(obj["event"])
            except json.JSONDecodeError:
                continue
    return events

# ── Group into sessions ────────────────────────────────────────
def build_sessions(events):
    ssh_sessions = {}
    http_by_ip   = defaultdict(list)

    for ev in events:
        proto  = ev.get("Protocol", "")
        status = ev.get("Status", "")
        sid    = ev.get("ID", "")

        if proto == "SSH":
            if status == "Stateless":
                if sid not in ssh_sessions:
                    ssh_sessions[sid] = {
                        "session_id":  sid,
                        "protocol":    "SSH",
                        "source_ip":   ev.get("SourceIp",""),
                        "source_port": ev.get("SourcePort",""),
                        "user":        ev.get("User",""),
                        "password":    ev.get("Password",""),
                        "client":      ev.get("Client",""),
                        "start_time":  ev.get("DateTime",""),
                        "end_time":    "",
                        "duration_s":  None,
                        "commands":    [],
                        "description": ev.get("Description",""),
                    }
            elif status == "Start":
                if sid not in ssh_sessions:
                    ssh_sessions[sid] = {
                        "session_id":  sid,
                        "protocol":    "SSH",
                        "source_ip":   ev.get("SourceIp",""),
                        "source_port": ev.get("SourcePort",""),
                        "user":        "", "password":    "",
                        "client":      "",
                        "start_time":  ev.get("DateTime",""),
                        "end_time":    "", "duration_s":  None,
                        "commands":    [],
                        "description": ev.get("Description",""),
                    }
            elif status == "Interaction":
                if sid in ssh_sessions:
                    ssh_sessions[sid]["commands"].append({
                        "time":   ev.get("DateTime",""),
                        "cmd":    ev.get("Command",""),
                        "output": ev.get("CommandOutput",""),
                    })
            elif status == "End":
                if sid in ssh_sessions:
                    ssh_sessions[sid]["end_time"] = ev.get("DateTime","")
                    try:
                        fmt = "%Y-%m-%dT%H:%M:%SZ"
                        t0  = datetime.strptime(ssh_sessions[sid]["start_time"], fmt)
                        t1  = datetime.strptime(ssh_sessions[sid]["end_time"],   fmt)
                        ssh_sessions[sid]["duration_s"] = int((t1-t0).total_seconds())
                    except Exception:
                        pass

        elif proto == "HTTP" and status == "Stateless":
            ip = ev.get("SourceIp","unknown")
            http_by_ip[ip].append({
                "time":       ev.get("DateTime",""),
                "method":     ev.get("HTTPMethod",""),
                "uri":        ev.get("RequestURI",""),
                "user_agent": ev.get("UserAgent",""),
                "body":       ev.get("Body",""),
                "headers":    ev.get("HeadersMap",{}),
                "host":       ev.get("HostHTTPRequest",""),
            })

    sessions = list(ssh_sessions.values())
    for ip, reqs in http_by_ip.items():
        sessions.append({
            "session_id":    f"http-{ip}-{reqs[0]['time']}",
            "protocol":      "HTTP",
            "source_ip":     ip,
            "start_time":    reqs[0]["time"],
            "end_time":      reqs[-1]["time"],
            "request_count": len(reqs),
            "requests":      reqs,
        })
    return sessions

# ── Build Ollama prompt ────────────────────────────────────────
def build_prompt(session):
    proto = session.get("protocol","")
    if proto == "SSH":
        cmds = "\n".join(
            f"  $ {c['cmd']}\n  > {c['output'][:300]}"
            for c in session.get("commands", [])
        ) or "  (no commands recorded)"
        return f"""You are a cybersecurity analyst reviewing a honeypot SSH session.
Respond ONLY with a valid JSON object — no markdown, no explanation.

Session:
  Source IP:  {session.get('source_ip','')}
  User/Pass:  {session.get('user','')}/{session.get('password','')}
  Client:     {session.get('client','')}
  Duration:   {session.get('duration_s','?')} seconds
  Start:      {session.get('start_time','')}

Commands:
{cmds}

JSON structure:
{{
  "threat_level": "critical|high|medium|low",
  "attack_type": "string",
  "attacker_intent": "one sentence",
  "key_indicators": ["list"],
  "commands_of_concern": ["list"],
  "data_accessed": "brief description",
  "recommended_action": "one sentence",
  "confidence": 0-100
}}"""
    else:
        reqs = session.get("requests", [])
        req_summary = "\n".join(
            f"  [{r['time']}] {r['method']} {r['uri']} UA:{r['user_agent'][:60]}"
            for r in reqs[:20]
        )
        return f"""You are a cybersecurity analyst reviewing honeypot HTTP attack traffic.
Respond ONLY with a valid JSON object — no markdown.

Source IP: {session.get('source_ip','')}
Requests: {session.get('request_count', len(reqs))}
Time: {session.get('start_time','')} → {session.get('end_time','')}

{req_summary}

JSON structure:
{{
  "threat_level": "critical|high|medium|low",
  "attack_type": "string",
  "attacker_intent": "one sentence",
  "key_indicators": ["list"],
  "paths_of_concern": ["list"],
  "recommended_action": "one sentence",
  "confidence": 0-100
}}"""

# ── Call Ollama ────────────────────────────────────────────────
def analyse_session(session):
    prompt = build_prompt(session)
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": [{"role":"user","content":prompt}],
                "stream": False,
                "options": {"temperature": 0.2},
            },
            timeout=180,
        )
        resp.raise_for_status()
        content = resp.json()["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        return json.loads(content)
    except requests.exceptions.Timeout:
        return {"error": "Ollama timeout", "threat_level": "unknown"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse failed: {e}", "threat_level": "unknown"}
    except Exception as e:
        return {"error": str(e), "threat_level": "unknown"}

# ── Load / save report ─────────────────────────────────────────
def load_report():
    if not os.path.exists(REPORT_PATH):
        return {"generated_at": None, "total_sessions": 0, "sessions": []}
    try:
        with open(REPORT_PATH) as f:
            return json.load(f)
    except Exception:
        return {"generated_at": None, "total_sessions": 0, "sessions": []}

def save_report(report):
    os.makedirs("logs", exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

# ── Analyse a single session by ID — used by FastAPI streaming ─
def analyse_one(session_id):
    """
    Generator that yields progress dicts and finally the result.
    Designed to be consumed by a FastAPI StreamingResponse.
    """
    def emit(step, pct, msg, data=None):
        payload = {"step": step, "pct": pct, "msg": msg}
        if data:
            payload["data"] = data
        return "data: " + json.dumps(payload) + "\n\n"

    yield emit("parse", 10, "Reading honeypot log file…")

    events   = parse_log()
    sessions = build_sessions(events)

    target = next((s for s in sessions if s.get("session_id") == session_id), None)
    if not target:
        yield emit("error", 0, f"Session {session_id} not found in log")
        return

    proto  = target.get("protocol","?")
    n_cmds = len(target.get("commands", target.get("requests", [])))
    yield emit("session", 25, f"Found {proto} session — {n_cmds} interactions from {target.get('source_ip','?')}")

    yield emit("ollama", 45, f"Sending to Llama3:8b for analysis…")

    analysis = analyse_session(target)

    yield emit("save", 80, "Saving result to report…")

    # Merge into existing report
    report = load_report()
    existing_ids = [item["session"]["session_id"] for item in report["sessions"]]

    result = {
        "session":     target,
        "analysis":    analysis,
        "analysed_at": datetime.now(timezone.utc).isoformat(),
    }

    if session_id in existing_ids:
        idx = existing_ids.index(session_id)
        report["sessions"][idx] = result
    else:
        report["sessions"].append(result)

    report["total_sessions"] = len(report["sessions"])
    report["generated_at"]   = datetime.now(timezone.utc).isoformat()
    save_report(report)

    yield emit("done", 100, "Analysis complete", data=result)

# ── Full run (all sessions) ────────────────────────────────────
def run():
    events   = parse_log()
    sessions = build_sessions(events)
    print(f"[analyser] {len(events)} events → {len(sessions)} sessions")

    report = load_report()
    existing_ids = {item["session"]["session_id"] for item in report["sessions"]}

    for i, sess in enumerate(sessions):
        sid = sess.get("session_id","")
        if sid in existing_ids:
            print(f"[analyser] [{i+1}/{len(sessions)}] {sid} already analysed, skipping")
            continue
        print(f"[analyser] [{i+1}/{len(sessions)}] Analysing {sess.get('protocol')} {sess.get('source_ip')}…")
        analysis = analyse_session(sess)
        report["sessions"].append({
            "session":     sess,
            "analysis":    analysis,
            "analysed_at": datetime.now(timezone.utc).isoformat(),
        })
        print(f"[analyser]   → {analysis.get('threat_level','?')}")

    report["total_sessions"] = len(report["sessions"])
    report["generated_at"]   = datetime.now(timezone.utc).isoformat()
    save_report(report)
    print(f"[analyser] Report written to {REPORT_PATH}")

if __name__ == "__main__":
    run()
