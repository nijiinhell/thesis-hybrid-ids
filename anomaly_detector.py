import os
import subprocess

# Auto-install dependencies
try:
    import pyshark, pandas as pd, numpy as np
    from sklearn.preprocessing import MinMaxScaler
    from sklearn.model_selection import train_test_split
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, Dense
except ImportError:
    print("🔧 Installing missing packages...")
    subprocess.check_call(["pip", "install", "pyshark", "pandas", "numpy", "scikit-learn", "tensorflow"])

import pyshark
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

# STEP 1: Extract Features from PCAP
print("📥 Parsing PCAP file...")
cap = pyshark.FileCapture("2021-09-14-agenttesla.pcap", use_json=True, include_raw=True)

data = []
for pkt in cap:
    data.append({
        "frame.len": int(pkt.frame_info.len),
        "frame.time_epoch": float(pkt.frame_info.time_epoch)
    })
cap.close()

df = pd.DataFrame(data)
df["time_diff"] = df["frame.time_epoch"].diff().fillna(0)  # Optional: add temporal behavior
df.to_csv("agenttesla_features.csv", index=False)
print(f"✅ Saved extracted features to agenttesla_features.csv ({len(df)} samples)")

# STEP 2: Normalize & Train Autoencoder
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

print("🧠 Training autoencoder...")
autoencoder.fit(X_train, X_train,
                epochs=50,
                batch_size=32,
                shuffle=True,
                validation_data=(X_test, X_test),
                verbose=0)

# STEP 3: Anomaly Detection
X_test_pred = autoencoder.predict(X_test)
reconstruction_error = np.mean(np.square(X_test - X_test_pred), axis=1)
threshold = np.percentile(reconstruction_error, 95)
anomalies = reconstruction_error > threshold
anomaly_count = np.sum(anomalies)

# Feature contribution
feature_errors = np.mean(np.abs(X_test - X_test_pred), axis=0)
feature_contributions = pd.Series(feature_errors, index=df.columns).sort_values(ascending=False)

print(f"\n✅ Anomalies Detected: {anomaly_count} out of {len(X_test)} samples")
print("\n🔍 Top Contributing Features:")
print(feature_contributions)

flagged = pd.DataFrame(X_test[anomalies], columns=df.columns)
flagged.to_csv("flagged_anomalies.csv", index=False)
print("\n📄 Flagged anomalies saved to 'flagged_anomalies.csv'")
