import os
import time
import subprocess
import pyshark
import pandas as pd
from pymongo import MongoClient
from collections import defaultdict
from datetime import datetime

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017"
DATABASE_NAME = "network_traffic"
COLLECTION_NAME = "features"

# Initialize MongoDB client
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

# Initialize Flow
def initialize_flow():
    return {
        'Dst Port': 0, 'Protocol': None, 'Timestamp': None, 'Flow Duration': 0,
        'Tot Fwd Pkts': 0, 'Tot Bwd Pkts': 0, 'TotLen Fwd Pkts': 0, 'TotLen Bwd Pkts': 0,
        'Fwd Pkt Len Max': 0, 'Fwd Pkt Len Min': float('inf'), 'Fwd Pkt Len Mean': 0, 'Fwd Pkt Len Std': [],
        'Bwd Pkt Len Max': 0, 'Bwd Pkt Len Min': float('inf'), 'Bwd Pkt Len Mean': 0, 'Bwd Pkt Len Std': [],
        'Flow Byts/s': 0, 'Flow Pkts/s': 0,
        'Flow IAT Mean': 0, 'Flow IAT Std': [], 'Flow IAT Max': 0, 'Flow IAT Min': float('inf'),
        'Fwd IAT Tot': 0, 'Fwd IAT Mean': 0, 'Fwd IAT Std': [], 'Fwd IAT Max': 0, 'Fwd IAT Min': float('inf'),
        'Bwd IAT Tot': 0, 'Bwd IAT Mean': 0, 'Bwd IAT Std': [], 'Bwd IAT Max': 0, 'Bwd IAT Min': float('inf'),
        'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0,
        'Fwd Header Len': 0, 'Bwd Header Len': 0, 'Fwd Pkts/s': 0, 'Bwd Pkts/s': 0,
        'Pkt Len Min': float('inf'), 'Pkt Len Max': 0, 'Pkt Len Mean': 0, 'Pkt Len Std': [],
        'Pkt Len Var': 0, 'FIN Flag Cnt': 0, 'SYN Flag Cnt': 0, 'RST Flag Cnt': 0, 'PSH Flag Cnt': 0,
        'ACK Flag Cnt': 0, 'URG Flag Cnt': 0, 'CWE Flag Count': 0, 'ECE Flag Cnt': 0,
        'Down/Up Ratio': 0, 'Pkt Size Avg': 0, 'Fwd Seg Size Avg': 0, 'Bwd Seg Size Avg': 0,
        'Fwd Byts/b Avg': 0, 'Fwd Pkts/b Avg': 0, 'Fwd Blk Rate Avg': 0, 'Bwd Byts/b Avg': 0,
        'Bwd Pkts/b Avg': 0, 'Bwd Blk Rate Avg': 0, 'Subflow Fwd Pkts': 0, 'Subflow Fwd Byts': 0,
        'Subflow Bwd Pkts': 0, 'Subflow Bwd Byts': 0, 'Init Fwd Win Byts': 0, 'Init Bwd Win Byts': 0,
        'Fwd Act Data Pkts': 0, 'Fwd Seg Size Min': 0, 'Active Mean': 0, 'Active Std': [], 'Active Max': 0,
        'Active Min': 0, 'Idle Mean': 0, 'Idle Std': [], 'Idle Max': 0, 'Idle Min': 0
    }

# Process Packet
def process_packet(pkt, flows):
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        protocol = pkt.transport_layer
        dst_port = int(pkt[pkt.transport_layer].dstport)
        timestamp = float(pkt.sniff_timestamp)
        pkt_len = int(pkt.length)

        # Flow Key
        flow_key = (src_ip, dst_ip, protocol)
        if flow_key not in flows:
            flows[flow_key] = initialize_flow()

        flow = flows[flow_key]
        flow['Dst Port'] = dst_port
        flow['Protocol'] = protocol
        flow['Timestamp'] = flow['Timestamp'] or timestamp
        flow['Flow Duration'] = (timestamp - flow['Timestamp']) * 1e6  # microseconds

        # Update Packet Counts
        if src_ip == flow_key[0]:
            flow['Tot Fwd Pkts'] += 1
            flow['TotLen Fwd Pkts'] += pkt_len
        else:
            flow['Tot Bwd Pkts'] += 1
            flow['TotLen Bwd Pkts'] += pkt_len

    except AttributeError:
        pass

# Compute Flow Metrics
def compute_flow_metrics(flows):
    rows = []
    for flow_key, flow in flows.items():
        rows.append(flow)
    return pd.DataFrame(rows)

# Process PCAP
def process_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp or udp")
    flows = defaultdict(initialize_flow)
    for pkt in cap:
        process_packet(pkt, flows)
    cap.close()
    return compute_flow_metrics(flows)

# Main Loop
def main():
    print("\nWelcome to the Automated Traffic Capture and Analysis System!")
    print("Sit back, relax, and watch the magic happen...\n")
    print("=" * 50)

    while True:
        try:
            print(f"[{datetime.now()}] 🚀 Starting traffic capture...")
            # Capture traffic for 10 seconds
            subprocess.run(["tshark", "-i", "eth0", "-a", "duration:10", "-w", "capture.pcap"], check=True)

            print(f"[{datetime.now()}] 📊 Processing captured traffic...")
            # Process the capture.pcap file
            df = process_pcap("capture.pcap")

            print(f"[{datetime.now()}] 💾 Saving extracted features to 'extracted_features.csv'...")
            df.to_csv("extracted_features.csv", index=False)

            print(f"[{datetime.now()}] 📤 Sending extracted features to MongoDB...")
            records = df.to_dict(orient="records")
            collection.insert_many(records)
            print(f"[{datetime.now()}] ✅ Data successfully inserted into MongoDB!")

        except Exception as e:
            print(f"[{datetime.now()}] ❌ Error occurred: {e}")

        finally:
            # Clean up temporary files
            if os.path.exists("capture.pcap"):
                os.remove("capture.pcap")
                print(f"[{datetime.now()}] 🗑️ Deleted temporary file: 'capture.pcap'")
            if os.path.exists("extracted_features.csv"):
                os.remove("extracted_features.csv")
                print(f"[{datetime.now()}] 🗑️ Deleted temporary file: 'extracted_features.csv'")

            print("=" * 50)

        # Wait before starting next capture
        print(f"[{datetime.now()}] ⏳ Waiting 10 seconds for the next capture...\n")
        time.sleep(10)

if __name__ == "__main__":
    main()

