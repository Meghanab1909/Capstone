from flask import Flask
import time

app = Flask(__name__)

@app.route("/")
def home():
    return "IoT Device: OK\n"

@app.route("/status")
def status():
    return {"status": "normal", "uptime": time.time()}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
