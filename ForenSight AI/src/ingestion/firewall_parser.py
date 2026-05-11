"""
Firewall CSV Parser
-------------------

Processes CIC IDS network flow dataset.

Reference:
Canadian Institute for Cybersecurity (CIC IDS 2017)
https://www.unb.ca/cic/datasets/ids-2017.html
"""

import pandas as pd            # Used for data manipulation and analysis with DataFrames
from datetime import datetime  # Used to convert string timestamps into datetime objects


def parse_firewall_csv(file_path):
    
    # Load dataset
    df = pd.read_csv(file_path)

    # Remove leading/trailing spaces from column names
    df.columns = df.columns.str.strip()

    # Separate BENIGN and ATTACK traffic
    benign = df[df["Label"] == "BENIGN"]
    attacks = df[df["Label"] != "BENIGN"]

    # If attack rows exist, create a balanced sample
    if len(attacks) > 0:

        benign_sample = benign.sample(n=1000, random_state=42)
        attack_sample = attacks.sample(n=1000, random_state=42)

        df = pd.concat([benign_sample, attack_sample])

    else:
        # Some datasets (like Tuesday) contain only benign traffic
        df = benign.sample(n=2000, random_state=42)

    parsed_logs = []

    # Iterate through each row in the dataset
    for _, row in df.iterrows():
        
        destination_port = row.get("Destination Port")
        label = row.get("Label")

        # Build message field
        message = f"DestPort:{destination_port} | Label:{label}"

        log = {
            "timestamp": datetime.now(),   # Placeholder timestamp
            "source_ip": None,
            "destination_ip": None,
            "username": None,
            "request_method": None,
            "endpoint": destination_port,
            "status_code": None,
            "message": message,
            "log_type": "firewall"
        }

        # Add parsed record to list
        parsed_logs.append(log)

    return parsed_logs