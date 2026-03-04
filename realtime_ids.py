# ===============================
# Imports
# ===============================
import csv
from datetime import datetime
import os

import pandas as pd
import numpy as np
import joblib
import time

from tensorflow.keras.models import load_model
from tensorflow.keras.losses import MeanSquaredError


# ===============================
# Load trained IDS artifacts
# ===============================

ARTIFACT_DIR = "artifacts/"

mc_autoencoder = load_model(
    ARTIFACT_DIR + "mc_autoencoder.h5",
    custom_objects={"mse": MeanSquaredError()}
)

scaler = joblib.load(ARTIFACT_DIR + "scaler.pkl")
error_threshold = joblib.load(ARTIFACT_DIR + "error_threshold.pkl")
fusion_params = joblib.load(ARTIFACT_DIR + "fusion_params.pkl")
train_columns = joblib.load(ARTIFACT_DIR + "train_columns.pkl")

alpha = fusion_params["alpha"]
fusion_threshold = fusion_params["fusion_threshold"]


# ===============================
# MC Dropout prediction
# ===============================

def mc_dropout_predict(model, X, T=20):
    preds = []
    for _ in range(T):
        preds.append(model(X, training=True).numpy())
    return np.array(preds)


# ===============================
# Fused anomaly detection
# ===============================

def fused_anomaly_detection(X_scaled, model, alpha, fusion_threshold, T=20):
    mc_recons = mc_dropout_predict(model, X_scaled, T=T)

    mean_recon = mc_recons.mean(axis=0)
    var_recon = mc_recons.var(axis=0)

    recon_error = ((X_scaled - mean_recon) ** 2).mean(axis=1)
    uncertainty = var_recon.mean(axis=1)

    err_norm = (recon_error - recon_error.min()) / (
        recon_error.max() - recon_error.min() + 1e-8
    )
    unc_norm = (uncertainty - uncertainty.min()) / (
        uncertainty.max() - uncertainty.min() + 1e-8
    )

    final_score = err_norm + alpha * unc_norm
    alerts = (final_score > fusion_threshold).astype(int)

    return final_score, alerts


# ===============================
# Flow → NSL-KDD feature mapping
# ===============================

def map_flow_to_nslkdd(flow_df):
    df = pd.DataFrame()

    df["duration"] = flow_df["duration"]
    df["protocol_type"] = flow_df["protocol"]
    df["service"] = flow_df["service"]
    df["flag"] = flow_df["flag"]

    df["src_bytes"] = flow_df["src_bytes"]
    df["dst_bytes"] = flow_df["dst_bytes"]

    zero_features = [
        "land","wrong_fragment","urgent","hot",
        "num_failed_logins","logged_in","num_compromised",
        "root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files",
        "num_outbound_cmds","is_host_login","is_guest_login"
    ]
    for f in zero_features:
        df[f] = 0

    df["count"] = flow_df["count"]
    df["srv_count"] = flow_df["srv_count"]

    df["same_srv_rate"] = 0
    df["diff_srv_rate"] = 0
    df["srv_diff_host_rate"] = 0

    host_features = [
        "dst_host_count","dst_host_srv_count",
        "dst_host_same_srv_rate","dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
        "dst_host_serror_rate","dst_host_srv_serror_rate",
        "dst_host_rerror_rate","dst_host_srv_rerror_rate"
    ]
    for f in host_features:
        df[f] = 0

    return df


# ===============================
# Prepare real-time features
# ===============================

def prepare_realtime_features(nsl_df, train_columns, scaler):
    df_enc = pd.get_dummies(
        nsl_df,
        columns=["protocol_type", "service", "flag"]
    )
    df_enc = df_enc.reindex(columns=train_columns, fill_value=0)
    return scaler.transform(df_enc)


# ===============================
# Initialize IDS output file
# ===============================

OUTPUT_FILE = "ids_output.csv"

if not os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "round", "flow_id", "score", "status"])


# ===============================
# MAIN LOOP
# ===============================

if __name__ == "__main__":
    print("Real-time IDS started (CSV demo)")
    print("Running for 10 rounds...\n")

    MAX_ROUNDS = 10

    for round_id in range(1, MAX_ROUNDS + 1):
        print(f"🔁 Round {round_id}/{MAX_ROUNDS}")

        flow_df = pd.read_csv("flow_input.csv")

        nsl_df = map_flow_to_nslkdd(flow_df)
        X_scaled = prepare_realtime_features(
            nsl_df,
            train_columns,
            scaler
        )

        scores, alerts = fused_anomaly_detection(
            X_scaled,
            mc_autoencoder,
            alpha,
            fusion_threshold
        )

        print("--- Flow Analysis ---")
        with open(OUTPUT_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            for i in range(len(alerts)):
                status = "ANOMALY" if alerts[i] else "NORMAL"
                print(f"Flow {i} | Score={scores[i]:.4f} | {status}")
                writer.writerow([
                    datetime.now(),
                    round_id,
                    i,
                    float(scores[i]),
                    status
                ])

        print()
        time.sleep(5)

    print("Real-time IDS finished after 10 rounds")
