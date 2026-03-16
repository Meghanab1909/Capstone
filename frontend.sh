echo "[*] Starting Dashboard (FastAPI on port 8000)..."
echo "Dashboard available at: http://$(hostname -I | awk '{print $1}'):5000"
uvicorn dashboard.app:app --host 0.0.0.0 --port 8000 --reload
