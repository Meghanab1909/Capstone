"""
if_eval.py — IsolationForest accuracy/precision/recall/F1 via 5-fold CV.

Matches the same evaluation protocol as your existing reported IF numbers
(train on benign-only rows per fold, evaluate against ALL rows in that
fold — including malicious ones — using their known true labels).

Run from the project directory (needs logs/traffic_labeled.csv):
    python3 if_eval.py
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

CSV_PATH = "logs/traffic_labeled.csv"
IF_NUMERIC = ["src_port", "dst_port", "src_bytes", "dst_bytes", "flow_duration", "packet_count"]
N_FOLDS = 5


def main():
    df = pd.read_csv(CSV_PATH)
    df = df.dropna(subset=["label"])
    df = df.drop_duplicates(subset=["req_id"], keep="last")
    df["label"] = df["label"].astype(int)

    if_cols = [c for c in IF_NUMERIC if c in df.columns]
    X = df[if_cols].fillna(0).reset_index(drop=True)
    y = df["label"].reset_index(drop=True)

    print(f"[*] Dataset: {len(df)} rows ({(y==0).sum()} benign / {(y==1).sum()} malicious)")

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    fold_results = []

    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X, y), start=1):
        X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
        X_test,  y_test  = X.iloc[test_idx],  y.iloc[test_idx]

        # Train on BENIGN-ONLY rows from this fold's training split —
        # same principle as train_unsupervised() in hybrid_ai.py.
        benign_train = X_train[y_train == 0]

        contamination = round(float((y_train == 1).sum() / len(y_train)), 4)
        contamination = max(0.01, min(contamination, 0.499))

        iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
        iso.fit(benign_train)

        # sklearn IF: -1 = anomaly (predict malicious), 1 = normal (predict benign)
        raw_pred = iso.predict(X_test)
        y_pred = (raw_pred == -1).astype(int)

        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test, y_pred, zero_division=0)
        f1   = f1_score(y_test, y_pred, zero_division=0)

        fold_results.append({"fold": fold_idx, "accuracy": acc, "precision": prec,
                              "recall": rec, "f1": f1})
        print(f"[fold {fold_idx}] acc={acc:.4f}  prec={prec:.4f}  rec={rec:.4f}  f1={f1:.4f}")

    res_df = pd.DataFrame(fold_results)
    print("\n[*] 5-fold CV summary (mean ± std):")
    for metric in ["accuracy", "precision", "recall", "f1"]:
        print(f"    {metric:10s}: {res_df[metric].mean():.4f} ± {res_df[metric].std():.4f}")


if __name__ == "__main__":
    main()
