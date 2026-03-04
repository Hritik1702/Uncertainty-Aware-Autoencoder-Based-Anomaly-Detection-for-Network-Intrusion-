
---

#  Dataset

The system is trained using the **NSL-KDD dataset**, a widely used benchmark for intrusion detection research.

Dataset characteristics:

- Contains **41 network traffic features**
- Includes both **normal traffic and multiple attack types**
- Balanced version of the original KDD'99 dataset

Attack categories include:

- DoS (Denial of Service)
- Probe attacks
- R2L (Remote to Local)
- U2R (User to Root)

Training is performed **only on normal traffic** to enable anomaly-based detection.

---

# Model Design

## Autoencoder Architecture

The autoencoder learns compressed representations of normal network behavior.

```
Input Layer
↓
Encoder Layers
↓
Latent Representation
↓
Decoder Layers
↓
Reconstructed Input
```

The model is trained to **minimize reconstruction error**.

When anomalous traffic appears, reconstruction error increases significantly.

---

## Uncertainty Estimation (MC Dropout)

During inference, **Monte Carlo Dropout** performs multiple stochastic forward passes:

1. Run multiple predictions with dropout enabled
2. Compute mean reconstruction
3. Compute variance across predictions

Variance represents **model uncertainty**.

---

## Fusion-Based Anomaly Score

Final anomaly score:

```
Final Score = Reconstruction Error + α × Prediction Uncertainty
```

Where:

- **Reconstruction Error** detects deviations from normal behavior
- **Uncertainty** measures prediction instability
- **α** controls the influence of uncertainty

This improves detection reliability and reduces false positives.

---

# Evaluation Metrics

The model is evaluated using both **classification metrics** and **IDS-specific metrics**.

### Core Metrics

- Accuracy
- Precision
- Recall (Detection Rate)
- F1 Score

### IDS-Specific Metrics

- False Alarm Rate (FAR)
- Detection Rate (DR)

### Visualization

- Confusion Matrix
- ROC Curve
- Precision–Recall Curve
- Anomaly Score Distribution

These metrics provide a complete assessment of model performance.

---

#  Real-Time Deployment

The trained model is deployed using a **real-time detection script**.

### Detection Pipeline

1. Load trained model artifacts
2. Read network flow input data
3. Map features to training format
4. Scale input using trained scaler
5. Perform MC Dropout inference
6. Compute fusion anomaly score
7. Generate intrusion alerts
8. Log results for monitoring

---

#  Monitoring Dashboard

A **Gradio-based dashboard** is used to monitor the IDS.

The dashboard displays:

- Total network flows analyzed
- Number of anomalies detected
- Latest detection events
- Real-time monitoring information

This interface enables live monitoring of intrusion detection results.

---

#  Project Structure
