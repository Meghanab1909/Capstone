FROM python:3.10

WORKDIR /app

COPY traffic_capture/sniffer.py /app/sniffer.py

COPY ai_engine /app/ai_engine

RUN pip install pandas scikit-learn joblib numpy scapy

CMD ["python", "sniffer.py"]
