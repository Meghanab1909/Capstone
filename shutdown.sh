#!/bin/bash

echo "========================================"
echo " IoT Honeynet – Shutdown Script         "
echo "========================================"

echo "[1/4] Stopping running containers..."
docker compose down --remove-orphans

echo "[2/4] Pruning unused networks..."
docker network prune -f

echo "[3/4] Optional: stop dashboard (if running)"
pkill -f "uvicorn" >/dev/null 2>&1

echo "[4/4] Cleanup complete."
echo "System is fully stopped."
