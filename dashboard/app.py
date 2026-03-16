from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
import os
import subprocess
import requests
import time
import json
from datetime import datetime
import random

app = FastAPI()
templates = Jinja2Templates(directory="dashboard/templates")

CSV_PATH = "logs/traffic_labeled.csv"
LOGS_PATH = "logs/ai_logs.json"
METRICS_PATH = "logs/ai_metrics.json"

REQUEST_ID = 0

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

    return {"logs": entries[-200:]}  # return last 200 entries

@app.get("/gateway", response_class=HTMLResponse)
def gateway_page(request: Request):
    return templates.TemplateResponse(
        "gateway.html",
        {"request": request}
    )
