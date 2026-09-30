import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_validate, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import numpy as np

TON_PATH = "/home/meghana/iot-honeynet/datasets/ton_iot.csv"
OUT_MODEL = "/home/meghana/iot-honeynet/ai_engine/rf_gateway.pkl"

# 13-column gateway-compatible schema
GATEWAY_COLUMNS = [
    "req_id",
    "src_ip", "dst_ip",
    "src_port", "dst_port",
    "protocol",
    "src_bytes", "dst_bytes",
    "flow_duration",
    "packet_count",
    "conn_state",
    "timestamp",
    "label"
]

def protocol_to_number(proto):
    if proto == "tcp":
        return 6
    if proto == "udp":
        return 17
    if proto == "icmp":
        return 1
    return 0  # unknown

def prepare_ton_dataset():
    df = pd.read_csv(TON_PATH)

    # Convert protocol
    df["protocol"] = df["proto"].apply(protocol_to_number)

    # Gateway-compatible packet count
    df["packet_count"] = df["src_pkts"] + df["dst_pkts"]

    # Rename TON columns to gateway names
    df["flow_duration"] = df["duration"]

    # Add synthetic values
    df["req_id"] = range(1, len(df) + 1)
    df["timestamp"] = 0  # no timestamp in TON

    # Keep only the 13 required columns (.copy() avoids SettingWithCopyWarning)
    df_gateway = df[[
        "req_id",
        "src_ip", "dst_ip",
        "src_port", "dst_port",
        "protocol",
        "src_bytes", "dst_bytes",
        "flow_duration",
        "packet_count",
        "conn_state",
        "timestamp",
        "label"
    ]].copy()

    # TON label is numeric already
    df_gateway["label"] = df_gateway["label"].astype(int)
    return df_gateway

def train_model():
    df = prepare_ton_dataset()

    X = df.drop(columns=["label"])
    y = df["label"]

    # ----------------------------------------
    # TRAIN / TEST SPLIT (60% train, 40% test)
    # stratify=y ensures class balance is preserved in both splits
    # ----------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.4,
        random_state=42,
        stratify=y
    )

    print(f"[*] Dataset split — Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    categorical = ["src_ip", "dst_ip", "conn_state"]
    numeric = [c for c in X.columns if c not in categorical]

    pre = ColumnTransformer([
        ("num", "passthrough", numeric),
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical)
    ])

    rf = RandomForestClassifier(
        n_estimators=250,
        class_weight="balanced",
        random_state=42
    )

    pipe = Pipeline([
        ("preprocess", pre),
        ("rf", rf)
    ])

    # ----------------------------------------
    # 5-FOLD CROSS-VALIDATION (on training set)
    # Gives statistically robust performance estimate across 5 independent splits
    # ----------------------------------------
    print("[*] Running 5-fold cross-validation on training set...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = cross_validate(
        pipe, X_train, y_train,
        cv=cv,
        scoring=["accuracy", "precision", "recall", "f1"],
        n_jobs=-1  # use all CPU cores to speed up
    )

    print("\n=======================")
    print(" CROSS-VALIDATION RESULTS (5-Fold, Train Set)")
    print("=======================")
    for metric in ["accuracy", "precision", "recall", "f1"]:
        scores = cv_results[f"test_{metric}"]
        print(f"{metric.capitalize():<12} mean={scores.mean():.4f}  std={scores.std():.4f}  per-fold={[f'{s:.4f}' for s in scores]}")
    print("=======================\n")

    # Final model is trained on the full training set (all 5 folds combined)
    print("[*] Training final model on TON_IoT → Gateway 13-column format...")
    pipe.fit(X_train, y_train)

    # ----------------------------------------
    # MODEL PERFORMANCE METRICS (on held-out test set)
    # ----------------------------------------
    preds = pipe.predict(X_test)

    acc  = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec  = recall_score(y_test, preds, zero_division=0)
    f1   = f1_score(y_test, preds, zero_division=0)
    cm   = confusion_matrix(y_test, preds)

    print("\n=======================")
    print(" MODEL PERFORMANCE (Test Set — 40%)")
    print("=======================")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, preds, zero_division=0))
    print("=======================\n")

    # ----------------------------------------
    # SAVE MODEL
    # ----------------------------------------
    joblib.dump(pipe, OUT_MODEL)
    print("[+] Saved new model as", OUT_MODEL)

if __name__ == "__main__":
    train_model()
