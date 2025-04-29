# Autoencoder-Based Anomaly Detection for PCAP Flows

This project parses a `.pcap` file, extracts basic features using PyShark, and applies an autoencoder to detect anomalous flows.

## How It Works
1. Parses `2021-09-14-agenttesla.pcap` using PyShark.
2. Extracts frame-level statistics (length, timestamp).
3. Normalizes the dataset.
4. Trains an unsupervised autoencoder.
5. Flags anomalies based on reconstruction error (95th percentile).
6. Outputs:
   - `agenttesla_features.csv` – parsed packet features
   - `flagged_anomalies.csv` – flagged anomalous flows

## Install & Run
```bash
git clone https://github.com/yourusername/anomaly-detector
cd anomaly-detector
python anomaly_detector.py
