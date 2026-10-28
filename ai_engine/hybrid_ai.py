import pandas as pd
import numpy as np
import joblib
import os
import warnings

from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

from sklearn.ensemble import IsolationForest

# ── Paths ────────────────────────────────────────────────────────────────────
# Resolve relative to this file so paths work both on the host
# (/home/meghana/iot-honeynet/...) and inside the container (/app/...).
_HERE      = os.path.dirname(os.path.abspath(__file__))
_ROOT      = os.path.dirname(_HERE)          # one level up from ai_engine/
CSV_PATH   = os.path.join(_ROOT, "logs", "traffic_labeled.csv")
MODEL_PATH = os.path.join(_HERE, "rf_gateway.pkl")

# How many recent labeled rows to use for IsolationForest training
UNSUP_WINDOW = 200

# ── Features the RF model was trained on (must match model_train_v2.py) ──
RF_NUMERIC     = [
    "src_port", "dst_port",
    "duration",
    "src_bytes", "dst_bytes",
    "missed_bytes",
    "src_pkts", "dst_pkts",
    "src_ip_bytes", "dst_ip_bytes",
    "path_length",
    "has_sql_pattern", "has_xss_pattern", "has_traversal_pattern",
    "has_rce_pattern", "has_recon_cve_pattern",
]
RF_CATEGORICAL = ["proto", "service", "conn_state", "http_method"]
RF_FEATURES    = RF_NUMERIC + RF_CATEGORICAL

# ── Features available from the gateway CSV for IsolationForest ──────────────
# (Only columns the gateway actually populates — never use all-NaN columns)
IF_NUMERIC = [
    "src_port", "dst_port",
    "src_bytes", "dst_bytes",
    "flow_duration", "packet_count",
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def protocol_number_to_name(proto_int: int) -> str:
    """Convert numeric IP protocol to the string the RF model expects."""
    mapping = {6: "tcp", 17: "udp", 1: "icmp"}
    return mapping.get(int(proto_int), "unknown")


def build_rf_input(row: pd.DataFrame) -> pd.DataFrame:
    """
    Map a raw gateway row to the 13-column schema the RF model expects.

    Gateway CSV column  →  RF model column
    ─────────────────────────────────────────
    protocol (int)      →  proto   (str)
    flow_duration       →  duration
    [not in gateway]    →  missed_bytes    (default 0)
    [not in gateway]    →  src_pkts        (default 0)
    [not in gateway]    →  dst_pkts        (default 0)
    [not in gateway]    →  src_ip_bytes    (default 0)
    [not in gateway]    →  dst_ip_bytes    (default 0)
    [not in gateway]    →  service         (default '-')
    """
    rf_row = pd.DataFrame()

    # Direct mappings
    for col in ["src_port", "dst_port", "src_bytes", "dst_bytes", "conn_state"]:
        rf_row[col] = row[col].values

    # Renamed columns
    rf_row["duration"] = row["flow_duration"].values

    # Derived columns
    rf_row["proto"] = row["protocol"].apply(protocol_number_to_name).values

    # Columns the gateway does not log → fill with 0 / '-'
    # (RF model was trained on TON_IoT which has these; 0 is a neutral safe default)
    for col in ["missed_bytes", "src_pkts", "dst_pkts", "src_ip_bytes", "dst_ip_bytes"]:
        rf_row[col] = row[col].values if col in row.columns else 0

    rf_row["service"] = row["service"].values if "service" in row.columns else "-"

    # Path/payload-derived columns. Default to 0/"GET" for rows written before
    # this feature existed (no path info available for those) so old CSV rows
    # don't crash inference - they just look "neutral" rather than malicious.
    path_cols = ["path_length", "has_sql_pattern", "has_xss_pattern",
                 "has_traversal_pattern", "has_rce_pattern", "has_recon_cve_pattern"]
    for col in path_cols:
        rf_row[col] = row[col].values if col in row.columns else 0
    rf_row["http_method"] = row["http_method"].values if "http_method" in row.columns else "GET"

    # Return in the exact order the model pipeline expects
    return rf_row[RF_FEATURES]


# ── Load latest unlabeled flow ────────────────────────────────────────────────

def load_latest_flow() -> pd.DataFrame:
    """
    Return the most recent unlabeled row from the CSV.
    Rows with NaN label = not yet classified by the hybrid engine.
    """
    df = pd.read_csv(CSV_PATH)

    if "label" not in df.columns:
        # Entire file is unlabeled — treat last row as latest
        return df.tail(1).copy()

    unlabeled = df[df["label"].isna()]
    if unlabeled.empty:
        raise ValueError(
            "No unlabeled rows found in CSV. "
            "The gateway must append a row with label=NaN before running hybrid_ai."
        )

    return unlabeled.tail(1).copy()


# ── Load supervised RF model ──────────────────────────────────────────────────

def load_supervised():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Supervised model not found at '{MODEL_PATH}'. "
            "Train it first using model_train_fixed.py."
        )
    return joblib.load(MODEL_PATH)


# ── Train IsolationForest on recent labeled history ───────────────────────────

def train_unsupervised():
    df = pd.read_csv(CSV_PATH)

    # Keep only labeled (finalized) rows
    if "label" in df.columns:
        df = df.dropna(subset=["label"])

    # Drop duplicate req_ids — keep='last' ensures the most recent label
    # (hybrid result) is retained rather than an earlier NaN or stale value
    df = df.drop_duplicates(subset=["req_id"], keep="last")

    # Sort by index to preserve chronological order before taking the window
    df = df.sort_index().tail(UNSUP_WINDOW)

    if len(df) < 5:
        print("[!] Fewer than 5 labeled rows — using fallback (always normal).")

        class FallbackIF:
            def predict(self, X):
                return [1] * len(X)  # 1 = normal in sklearn IF convention

        return FallbackIF()

    # Use only the gateway-populated numeric columns (avoid all-NaN columns)
    available_if_cols = [c for c in IF_NUMERIC if c in df.columns]

    # Bug fix 1: Train on BENIGN-ONLY rows so IF learns what normal looks like.
    # Training on mixed data (benign + malicious) defeats the purpose of anomaly
    # detection — the model would treat attack patterns as part of the baseline.
    benign = df[df["label"] == 0]

    if len(benign) < 5:
        print("[!] Not enough benign rows for IsolationForest — using fallback.")

        class FallbackIF:
            def predict(self, X):
                return [1] * len(X)

        return FallbackIF()

    # Bug fix 2: Derive contamination from the true malicious ratio in the
    # labeled window instead of hardcoding 0.05. The actual ratio is ~35%
    # so 0.05 caused the model to massively underestimate anomalies.
    contamination = round(float((df["label"] == 1).sum() / len(df)), 4)
    contamination = max(0.01, min(contamination, 0.499))  # clamp to valid range

    X_if = benign[available_if_cols].fillna(0)

    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42
    )
    iso.fit(X_if)
    iso._if_columns = available_if_cols   # store so predict uses same cols
    print(f"[*] IF trained on {len(benign)} benign rows  contamination={contamination}")
    return iso


# ── Hybrid prediction ─────────────────────────────────────────────────────────

def hybrid_predict(latest: pd.DataFrame, sup_model, unsup_model):
    """
    Weighted hybrid decision using continuous scores from both models.

    RF  → 70%  continuous P(malicious) from predict_proba
    IF  → 30%  continuous anomaly score from score_samples
              normalized from raw IF range [0.3, 0.7+] to [0.0, 1.0]

    Threshold: 0.5
    """

    # ── Supervised prediction ────────────────────────────────────────────────
    rf_input = build_rf_input(latest)
    sup      = int(sup_model.predict(rf_input)[0])
    rf_prob  = sup_model.predict_proba(rf_input)[0][1]   # P(malicious)

    # ── Unsupervised prediction ──────────────────────────────────────────────
    if_cols   = getattr(unsup_model, "_if_columns", IF_NUMERIC)
    available = [c for c in if_cols if c in latest.columns]
    X_if      = latest[available].fillna(0)

    unsup_raw  = unsup_model.predict(X_if)[0]
    unsup      = 1 if unsup_raw == -1 else 0

    # Continuous anomaly score — higher = more anomalous
    raw_score  = float(-unsup_model.score_samples(X_if)[0])
    # Normalize to [0, 1]: IF scores typically range 0.3 (normal) to 0.7+ (anomaly)
    if_score   = max(0.0, min(1.0, (raw_score - 0.3) / 0.4))

    # ── Weighted combination ─────────────────────────────────────────────────
    RF_WEIGHT = 0.7
    IF_WEIGHT = 0.3
    score  = (RF_WEIGHT * rf_prob) + (IF_WEIGHT * if_score)
    hybrid = 1 if score >= 0.5 else 0

    print(f"[*] RF_prob={rf_prob:.3f}  "
          f"IF_raw={raw_score:.3f}  IF_norm={if_score:.3f}  "
          f"WeightedScore={score:.3f}  →  Hybrid={hybrid}")

    return sup, unsup, hybrid

# ── Append labeled row back to CSV ────────────────────────────────────────────

def append_labeled(latest: pd.DataFrame, label: int):
    """Write the classified row back to the CSV with its hybrid label."""
    row = latest.copy()
    row["label"] = label
    # Append without re-writing headers; preserve all columns the row has
    row.to_csv(CSV_PATH, mode="a", header=False, index=False)
    print("[+] Labeled row appended to CSV.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("[*] Loading latest unlabeled flow …")
    latest = load_latest_flow()

    print("[*] Loading supervised RF model …")
    sup_model = load_supervised()

    print("[*] Training IsolationForest on recent labeled history …")
    unsup_model = train_unsupervised()

    print("[*] Running hybrid inference …")
    sup, unsup, hybrid = hybrid_predict(latest, sup_model, unsup_model)

    label_str = "SUSPICIOUS" if hybrid == 1 else "benign"
    print(f"[+] Supervised={sup}  Unsupervised={unsup}  →  Hybrid={hybrid} ({label_str})")

    append_labeled(latest, hybrid)
    print("[+] Hybrid AI completed.")


if __name__ == "__main__":
    main()
