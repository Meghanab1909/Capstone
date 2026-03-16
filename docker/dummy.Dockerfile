FROM python:3.10-slim
WORKDIR /app
COPY dummy_device/dummy.py .
RUN pip install flask
CMD ["python", "dummy.py"]
