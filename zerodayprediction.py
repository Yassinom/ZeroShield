import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from pymongo import MongoClient
from pytorch_tabnet.tab_model import TabNetClassifier

def preprocess_for_zero_day_detection(model_path):
    """
    Fetch data from MongoDB, preprocess it to match the UGRansome model features, make predictions,
    and store results back into MongoDB.
    Args:
        model_path (str): Path to the trained TabNet_UGransome model.

    Returns:
        DataFrame: Processed dataset with predictions.
    """
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017")
    db = client["network_traffic"]
    input_collection = db["features"]
    output_collection = db["zerodaypredictions"]

    # Fetch data from MongoDB
    data = list(input_collection.find())
    input_df = pd.DataFrame(data)

    # Initialize empty DataFrame for final features
    output_df = pd.DataFrame()
    
    # Map 'Time' -> Use 'Flow Duration' (convert milliseconds to seconds)
    output_df['Time'] = input_df['Flow Duration'] // 1000

    # Encode 'Protocol'
    le = LabelEncoder()
    output_df['Protocol'] = le.fit_transform(input_df['Protocol'])
    
    # Fixed values for placeholders
    output_df['Flag'] = 0
    output_df['Family'] = 0
    output_df['Clusters'] = 1
    output_df['SedAddress'] = 0
    output_df['ExpAddress'] = 0
    output_df['BTC'] = 0
    output_df['USD'] = 0
    output_df['Netflow_Bytes'] = input_df['TotLen Fwd Pkts'] + input_df['TotLen Bwd Pkts']
    output_df['IPAddress'] = 0
    output_df['Threats'] = 0
    output_df['Port'] = input_df['Dst Port']

    # Load the trained TabNet model
    clf2 = TabNetClassifier()
    clf2.load_model("models/tabnet_UGransome.zip")

    # Ensure input tensor format for the model
    model_input = output_df.values

    # Make predictions
    predictions = clf2.predict(model_input)

    # Add predictions to the output DataFrame
    output_df['Prediction'] = predictions

    # Store results back into MongoDB
    results = output_df.to_dict(orient="records")
    output_collection.insert_many(results)

    print("Predictions successfully stored in MongoDB collection 'zerodaypredictions'.")
    return output_df

if __name__ == "__main__":
    output_df = preprocess_for_zero_day_detection("models/tabnet_UGransome.zip")
    print(output_df.head())

