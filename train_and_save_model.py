from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Flatten, Dense
import numpy as np

# Create dummy data
X = np.random.rand(500, 5, 1)         # 500 packets, 5 features each
y = np.random.randint(0, 2, 500)      # Binary labels (0=normal, 1=intrusive)

# Define simple Conv1D model
model = Sequential([
    Conv1D(32, kernel_size=2, activation='relu', input_shape=(5,1)),
    Flatten(),
    Dense(64, activation='relu'),
    Dense(1, activation='sigmoid')  # Binary output
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X, y, epochs=5)

# Save the model to conv1d_model.h5
model.save("conv1d_model.h5")
print("✅ Model saved as conv1d_model.h5")