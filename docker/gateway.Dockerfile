FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Gateway source + AI engine
COPY gateway/ /app/gateway/
COPY ai_engine/ /app/ai_engine/
COPY honeypot/templates/ /app/honeypot/templates/

# Logs dir (volume-mounted at runtime, but create it so the app starts clean)
RUN mkdir -p /app/logs

# Gateway listens on 8080 — only reachable from gateway_net (not published to host)
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=15s \
  CMD curl -sf http://localhost:8080/ || exit 1

CMD ["python3", "gateway/gateway.py"]
