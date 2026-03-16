FROM python:3.10-slim
WORKDIR /app
COPY iot_device/device.py .
RUN pip install flask
CMD ["python", "device.py"]

