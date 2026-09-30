import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# ------------------------------
# CONFIGURATION
# ------------------------------

TON_IOT_PATH = "datasets/ton_iot.csv"      # <-- Ground truth labeled dataset
MODEL_PATH = "ai_engine/models/random_forest.pkl"
PHASE0_TRAFFIC = "logs/traffic.csv"
PHASE0_OUTPUT = "logs/traffic_labeled.csv"

os.makedirs("ai_engine/models", exist_ok=True)

# ------------------------------
# TRAIN MODEL ON TON-IoT (ONCE)
# ------------------------------

def train_rf_once():
    print("Loading TON-IoT dataset...")
    df = pd.read_csv(TON_IOT_PATH)

    # ---------------------------
    # NORMALIZE COLUMN NAMES
    # ---------------------------

    rename_map = {}

    # Dynamically map columns
    if "src" in df.columns:
        rename_map["src"] = "src_ip"
    if "dst" in df.columns:
        rename_map["dst"] = "dst_ip"
    if "proto" in df.columns:
        rename_map["proto"] = "protocol"
    if "bytes" in df.columns:
        rename_map["bytes"] = "packet_size"
    if "pktcount" in df.columns:
        # If bytes missing, fallback to pktcount
        if "packet_size" not in rename_map.values():
            rename_map["pktcount"] = "packet_size"
    if "ts" in df.columns:
        rename_map["ts"] = "timestamp"
    if "attack" in df.columns:
        rename_map["attack"] = "label"

    df = df.rename(columns=rename_map)

    # ---------------------------
    # VALIDATE REQUIRED COLUMNS
    # ---------------------------

    required = ["src_ip", "dst_ip", "protocol", "packet_size", "timestamp", "label"]

    for col in required:
        if col not in df.columns:
            print(f"⚠ Missing column in TON-IoT: {col}. Filling default value.")
            if col == "protocol":
                df[col] = "unknown"
            elif col == "packet_size":
                df[col] = 0
            elif col == "timestamp":
                df[col] = 0
            elif col in ["src_ip", "dst_ip"]:
                df[col] = "0.0.0.0"

    # ---------------------------
    # ENCODING
    # ---------------------------

    for c in ["src_ip", "dst_ip", "protocol"]:
        df[c] = df[c].astype("category").cat.codes

    X = df[["src_ip", "dst_ip", "protocol", "packet_size", "timestamp"]]
    y = df["label"]

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X, y)

    # Holdout test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    preds = rf.predict(X_test)

    print("\nRandom Forest Evaluation:")
    print(classification_report(y_test, preds))

    joblib.dump(rf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


# ------------------------------
# APPLY RF TO PHASE-0 TRAFFIC
# ------------------------------

def apply_rf_to_phase0():
    print("Loading RF model...")
    rf = joblib.load(MODEL_PATH)

    df = pd.read_csv(PHASE0_TRAFFIC)

    FEATURES = ["src_ip", "dst_ip", "protocol", "packet_size", "timestamp"]

    # Encode for inference
    for col in ["src_ip", "dst_ip", "protocol"]:
        df[col] = df[col].astype("category").cat.codes

    print("Running inference...")
    df["label"] = rf.predict(df[FEATURES])

    df.to_csv(PHASE0_OUTPUT, index=False)
    print(f"Labeled traffic with RF saved to {PHASE0_OUTPUT}")

# ------------------------------
# MAIN LOGIC
# ------------------------------

if not os.path.exists(MODEL_PATH):
    print("Model not found. Training new RF model...")
    train_rf_once()
else:
    print("Model already exists. Skipping training.")

apply_rf_to_phase0()
