import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, Raw, wrpcap
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

# --- STEP 1: Load PCAP and Extract Data ---
print("Loading PCAP file and extracting relevant data...")
packets = rdpcap("2021-09-14-agenttesla.pcap")
data = []

for packet in packets:
    if hasattr(packet, 'time'):
        data.append({
            "frame.len": len(packet),
            "frame.time_epoch": packet.time
        })

df = pd.DataFrame(data)
df["time_diff"] = df["frame.time_epoch"].diff().fillna(0)
df.to_csv("agenttesla_features.csv", index=False)
print(f"Extracted {len(df)} packets and saved to agenttesla_features.csv")

# --- STEP 2: Normalize Data & Train Autoencoder ---
print("Normalizing data and training the autoencoder...")
df = df.select_dtypes(include=[np.number]).dropna()
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(df)
X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)

input_dim = X_train.shape[1]
input_layer = Input(shape=(input_dim,))
encoded = Dense(16, activation='relu')(input_layer)
encoded = Dense(8, activation='relu')(encoded)
decoded = Dense(16, activation='relu')(encoded)
decoded = Dense(input_dim, activation='sigmoid')(decoded)
autoencoder = Model(inputs=input_layer, outputs=decoded)
autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.fit(X_train, X_train, epochs=50, batch_size=32, shuffle=True, validation_data=(X_test, X_test), verbose=0)

# --- STEP 3: Identify Anomalies ---
print("Detecting anomalies in the data...")
X_test_pred = autoencoder.predict(X_test)
reconstruction_error = np.mean(np.square(X_test - X_test_pred), axis=1)
threshold = np.percentile(reconstruction_error, 95)
anomalies = reconstruction_error > threshold

feature_errors = np.mean(np.abs(X_test - X_test_pred), axis=0)
feature_contributions = pd.Series(feature_errors, index=df.columns).sort_values(ascending=False)

print(f"Anomalies found: {np.sum(anomalies)} out of {len(X_test)}")
print("Top contributing features:\n", feature_contributions)

flagged = pd.DataFrame(X_test[anomalies], columns=df.columns)
flagged.to_csv("flagged_anomalies.csv", index=False)
print("Anomalies saved to 'flagged_anomalies.csv'")

# --- STEP 4: Reconstruct Anomalies into PCAP Format for Snort ---
print("Rebuilding flagged anomalies into 'flagged_anomalies.pcap' for Snort...")
reconstructed_packets = []
for _, row in flagged.iterrows():
    frame_len = int(row.get("frame.len", 100))
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
    payload_len = max(10, frame_len - 40)
    pkt = pkt / Raw(load=bytes([0x41] * payload_len))  # Using 'A's as dummy payload
    reconstructed_packets.append(pkt)

wrpcap("flagged_anomalies.pcap", reconstructed_packets)
print("PCAP file for Snort ('flagged_anomalies.pcap') has been saved successfully.")
