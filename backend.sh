#!/bin/bash

echo "[*] Activating Python virtual environment..."
source /home/meghana/iot-honeynet/venv/bin/activate

docker compose down --remove-orphans >/dev/null 2>&1

docker network prune -f >/dev/null 2>&1

docker compose build

echo "[*] Starting scaled IoT environment..."
docker compose up -d \
  --scale real_iot=4 \
  --scale honeypot=2 \
  --scale dummy_iot=1 

echo "[*] Starting Gateway (port 8080)..."
python3 /home/meghana/iot-honeynet/gateway/gateway.py
