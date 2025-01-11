import numpy as np
import pandas as pd
from pymongo import MongoClient
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tensorflow.keras.models import load_model

# Step 1: Connect to MongoDB and load data
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["network_traffic"]
features_collection = db["features"]
predictions_collection = db["predictions"]

# Load data from MongoDB
data = pd.DataFrame(list(features_collection.find()))

# Drop '_id' as it's not needed for processing
if "_id" in data.columns:
    data.drop("_id", axis=1, inplace=True)

# Step 2: Preprocess the data
# Encode 'Protocol' column
if 'Protocol' in data.columns: 
    data['Protocol'] = LabelEncoder().fit_transform(data['Protocol'])  # Encode Protocol

# Replace arrays with their median values and empty arrays with 0
for col in data.columns:
    data[col] = data[col].apply(
        lambda x: np.median(x) if isinstance(x, list) and len(x) > 0 else (0 if isinstance(x, list) else x)
    )

# Replace inf values with NaN
data.replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill NaN values with column medians
data.fillna(data.median(numeric_only=True), inplace=True)

# Standardize numeric features
scaler = StandardScaler()
numeric_data = data.select_dtypes(include=[np.number])
data_scaled = scaler.fit_transform(numeric_data)

# Step 3: Load the trained autoencoder model
autoencoder = load_model('models/autoencoder_model.keras')

# Perform inference with the autoencoder
reconstructed_data = autoencoder.predict(data_scaled)
reconstruction_error = np.mean(np.power(data_scaled - reconstructed_data, 2), axis=1)

# Define the threshold for anomalies
threshold = np.percentile(reconstruction_error, 90)
anomalies = reconstruction_error > threshold

# Step 4: Add anomalies back to the original DataFrame
data['Anomaly'] = anomalies

# Step 5: Save results to MongoDB
records_to_insert = data.to_dict(orient="records")
predictions_collection.insert_many(records_to_insert)

print("Results saved successfully to the 'predictions' collection.")

