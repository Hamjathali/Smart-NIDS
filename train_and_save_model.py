import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

# =======================
# Load dataset
# =======================
df = pd.read_csv("kdd_test.csv")

# Map protocol to numeric
proto_map = {"icmp": 1, "tcp": 6, "udp": 17}

# Initialize flow tracker (simulate flow-based features)
flow_tracker = {}

# =======================
# Feature extraction
# =======================
features = []
for idx, row in df.iterrows():
    proto = proto_map.get(row["protocol_type"], 0)
    src_port = np.random.randint(1024, 65535)  # placeholder
    dst_port = np.random.randint(20, 1024)     # placeholder
    length = np.random.randint(40, 1500)       # placeholder
    flags = 0                                  # no flags in dataset

    # Flow-based ID
    flow_id = (row["protocol_type"], src_port, dst_port)
    now = idx

    if flow_id not in flow_tracker:
        flow_tracker[flow_id] = {"timestamps": [], "sizes": []}
    flow_tracker[flow_id]["timestamps"].append(now)
    flow_tracker[flow_id]["sizes"].append(length)

    # Flow features
    timestamps = flow_tracker[flow_id]["timestamps"]
    sizes = flow_tracker[flow_id]["sizes"]
    flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    packet_size_avg = np.mean(sizes)

    features.append([proto, src_port, dst_port, length, flags, flow_duration, packet_size_avg])

# Convert to array
X = np.array(features)

# =======================
# Binary Labels
# =======================
df["labels"] = df["labels"].replace(
    {"portsweep": "attack", "neptune": "attack", "smurf": "attack"}
)
y = np.where(df["labels"] == "normal", 0, 1)

# =======================
# Scale features
# =======================
scaler = StandardScaler()
X = scaler.fit_transform(X)

# =======================
# Train-test split
# =======================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# =======================
# Build model
# =======================
model = Sequential([
    Dense(64, activation="relu", input_shape=(X_train.shape[1],)),
    Dropout(0.3),
    Dense(32, activation="relu"),
    Dense(1, activation="sigmoid")
])

model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# Early stopping (prevent overfitting)
early_stop = EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True)

# =======================
# Train
# =======================
model.fit(
    X_train, y_train,
    epochs=15,
    batch_size=32,
    validation_data=(X_test, y_test),
    callbacks=[early_stop]
)

# =======================
# Save model
# =======================
model.save("binary_ids_model.h5")
print("✅ Binary IDS model trained and saved as binary_ids_model.h5")

