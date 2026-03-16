FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy ONLY gateway directory
COPY gateway/ /app/
COPY ai_engine /app/ai_engine

CMD ["python3", "gateway/gateway.py"]

