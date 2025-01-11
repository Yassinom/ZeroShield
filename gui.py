import customtkinter as ctk
from pymongo import MongoClient
import subprocess

# MongoDB Connection Configuration
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "network_traffic"
PREDICTIONS_COLLECTION = "predictions"
ZERODAY_COLLECTION = "zerodaypredictions"

def fetch_data_from_mongodb(collection_name):
    try:
        client = MongoClient(MONGO_URI)
        db = client[DATABASE_NAME]
        collection = db[collection_name]

        if collection_name == ZERODAY_COLLECTION:
            return list(collection.find())  # Return raw data for zeroday predictions
        else:
            # Count total packets, sane packets, and malicious packets
            total = collection.count_documents({})
            sane = collection.count_documents({"Anomaly": False})
            malicious = collection.count_documents({"Anomaly": True})
            connection_status.set("Connected")
            return {"total": total, "sane": sane, "malicious": malicious}
    except Exception as e:
        connection_status.set("Failed to Connect")
        print(f"Error fetching data: {e}")
        return {"total": 0, "sane": 0, "malicious": 0}

def run_zeroday_prediction_script():
    try:
        subprocess.run(["python", "zerodayprediction.py"], check=True)
        print("Zero-day predictions updated successfully.")
    except Exception as e:
        print(f"Error running prediction script: {e}")

def update_values():
    # Refresh main statistics
    data = fetch_data_from_mongodb(PREDICTIONS_COLLECTION)
    total_var.set(f"{data['total']:,}")
    sane_var.set(f"{data['sane']:,}")
    malicious_var.set(f"{data['malicious']:,}")
    status_var.set("Data fetched successfully!" if data["total"] > 0 else "No data found")
    status_label.configure(text_color="green" if data["total"] > 0 else "red")

    # Run prediction script and update zeroday data
    run_zeroday_prediction_script()
    zeroday_data = fetch_data_from_mongodb(ZERODAY_COLLECTION)
    update_zeroday_section(zeroday_data)

def update_zeroday_section(data):
    # Clear existing content
    for widget in zeroday_frame.winfo_children():
        widget.destroy()

    # Display headers
    ctk.CTkLabel(zeroday_frame, text="Protocol", font=table_header_font).grid(row=0, column=0, padx=5)
    ctk.CTkLabel(zeroday_frame, text="Netflow_Bytes", font=table_header_font).grid(row=0, column=1, padx=5)
    ctk.CTkLabel(zeroday_frame, text="Port", font=table_header_font).grid(row=0, column=2, padx=5)
    ctk.CTkLabel(zeroday_frame, text="Prediction", font=table_header_font).grid(row=0, column=3, padx=5)

    # Limit the display to the first 5 packets
    limited_data = data[:5]

    # Populate table rows
    for idx, packet in enumerate(limited_data):
        protocol = "TCP" if packet["Protocol"] == 1 else "UDP"
        netflow_bytes = f"{packet['Netflow_Bytes']} Bytes"
        port = packet["Port"]
        prediction = "Anomalie" if packet["Prediction"] == 0 else "Signature" if packet["Prediction"] == 1 else "Synthetic signature"

        ctk.CTkLabel(zeroday_frame, text=protocol, font=table_body_font).grid(row=idx+1, column=0, padx=5)
        ctk.CTkLabel(zeroday_frame, text=netflow_bytes, font=table_body_font).grid(row=idx+1, column=1, padx=5)
        ctk.CTkLabel(zeroday_frame, text=port, font=table_body_font).grid(row=idx+1, column=2, padx=5)
        ctk.CTkLabel(zeroday_frame, text=prediction, font=table_body_font).grid(row=idx+1, column=3, padx=5)

def create_dashboard():
    # Initialize the main application window
    root = ctk.CTk()
    root.title("Modern Packet Monitoring Dashboard")
    root.geometry("1000x700")
    root.resizable(False, False)

    # StringVars
    global total_var, sane_var, malicious_var, status_var, connection_status, status_label
    global zeroday_frame, table_header_font, table_body_font

    total_var = ctk.StringVar(value="0")
    sane_var = ctk.StringVar(value="0")
    malicious_var = ctk.StringVar(value="0")
    status_var = ctk.StringVar(value="Waiting for refresh...")
    connection_status = ctk.StringVar(value="Not Connected")

    header_font = ("Roboto", 24, "bold")
    value_font = ("Roboto", 40, "bold")
    status_font = ("Roboto", 16)
    table_header_font = ("Roboto", 14, "bold")
    table_body_font = ("Roboto", 12)

    # Layout
    header_frame = ctk.CTkFrame(root, corner_radius=15)
    header_frame.pack(fill="x", pady=(10, 10), padx=20)

    body_frame = ctk.CTkFrame(root, corner_radius=15)
    body_frame.pack(expand=True, fill="both", padx=20, pady=10)

    footer_frame = ctk.CTkFrame(root, corner_radius=15)
    footer_frame.pack(fill="x", padx=20, pady=(0, 10))

    zeroday_frame = ctk.CTkScrollableFrame(body_frame, corner_radius=15, fg_color="#2c3e50", height=300)
    zeroday_frame.pack(fill="x", padx=10, pady=10)

    # Header and cards
    ctk.CTkLabel(header_frame, text="Zero-Day Monitoring Agent", font=header_font, text_color="white").pack(pady=10)
    cards_frame = ctk.CTkFrame(body_frame, fg_color="transparent")
    cards_frame.pack(fill="x", padx=10)

    total_card = ctk.CTkFrame(cards_frame, corner_radius=15, fg_color="#34495e")
    total_card.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    ctk.CTkLabel(total_card, text="Total Received Packets", font=header_font, text_color="white").pack(pady=(20, 5))
    ctk.CTkLabel(total_card, textvariable=total_var, font=value_font, text_color="#3498db").pack(pady=(5, 20))

    sane_card = ctk.CTkFrame(cards_frame, corner_radius=15, fg_color="#2ecc71")
    sane_card.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
    ctk.CTkLabel(sane_card, text="Sane Packets", font=header_font, text_color="white").pack(pady=(20, 5))
    ctk.CTkLabel(sane_card, textvariable=sane_var, font=value_font, text_color="white").pack(pady=(5, 20))

    malicious_card = ctk.CTkFrame(cards_frame, corner_radius=15, fg_color="#e74c3c")
    malicious_card.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
    ctk.CTkLabel(malicious_card, text="Malicious Packets", font=header_font, text_color="white").pack(pady=(20, 5))
    ctk.CTkLabel(malicious_card, textvariable=malicious_var, font=value_font, text_color="white").pack(pady=(5, 20))

    # Refresh button
    refresh_button = ctk.CTkButton(footer_frame, text="🔄 Refresh", command=update_values, font=status_font)
    refresh_button.pack(pady=10)

    # Status label
    status_label = ctk.CTkLabel(footer_frame, textvariable=status_var, font=status_font)
    status_label.pack(side="left", padx=(10, 20))

    update_values()  # Initialize values
    root.mainloop()

if __name__ == "__main__":
    create_dashboard()

