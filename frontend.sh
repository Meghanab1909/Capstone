#!/bin/bash

echo "[*] Activating Python virtual environment..."
source /home/meghana/iot-honeynet/venv/bin/activate

echo "[*] Starting Dashboard..."
echo "Dashboard available at: http://$(hostname -I | awk '{print $1}'):8000"
uvicorn dashboard.app:app --host 0.0.0.0 --port 8000 --reload
