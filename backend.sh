#!/bin/bash

echo "[*] Connecting to TV display..."
xrandr --output $(xrandr | grep "HDMI.* connected" | awk '{print $1}') --same-as eDP-1

echo "[*] Activating Python virtual environment..."
source /home/meghana/iot-honeynet/venv/bin/activate

echo "[*] Tearing down any existing stack..."
docker compose down --remove-orphans >/dev/null 2>&1

echo "[*] Pruning stale networks..."
docker network prune -f >/dev/null 2>&1

echo "[*] Building images..."
docker compose build

echo "[*] Starting IoT Honeynet (Nginx → Gateway → 12 devices)..."
docker compose up -d

echo ""
echo "[✓] Stack is up."
echo "    Nginx virtual layer : http://$(hostname -I | awk '{print $1}'):80"
echo "    (Gateway + devices are internal — no direct host access)"
echo ""
echo "[*] Following gateway logs (Ctrl-C to stop)..."
docker compose logs -f gateway
