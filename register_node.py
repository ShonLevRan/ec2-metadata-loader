# register_node.py

import os
import json
import boto3
import requests
from requests.exceptions import RequestException

METADATA_BASE_URL = "http://169.254.169.254/latest/"
METADATA_TIMEOUT = 1.0

def get_imdsv2_token():
    try:
        response = requests.put(METADATA_BASE_URL + "api/token",
                                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                                timeout=METADATA_TIMEOUT)
        response.raise_for_status()
        return response.text
    except RequestException as e:
        print(f"Error fetching IMDSv2 token: {e}")
        return None

def get_metadata(path, token):
    try:
        response = requests.get(METADATA_BASE_URL + "meta-data/" + path, headers={"X-aws-ec2-metadata-token": token}, timeout=METADATA_TIMEOUT)
        response.raise_for_status()
        return response.text
    except RequestException as e:
        print(f"Error fetching metadata: {e}")
        return None

def register_node():
    token = get_imdsv2_token()
    if not token:
        print("Failed to fetch IMDSv2 token. Exiting.")
        return

    node_name = get_metadata("hostname", token)
    node_ip = get_metadata("local-ipv4", token)
    availability_zone = get_metadata("placement/availability-zone", token)
    # pods_ip_ranges = get_metadata("network/interfaces/macs/*/subnet-ipv4-cidr-block", token)

    # if node_name and node_ip and pods_ip_ranges:
    if node_name and node_ip and availability_zone:
        node_data = {
            "node_name": node_name,
            "node_ip": node_ip, 
            "availability_zone": availability_zone
            # "pods_ip_ranges": pods_ip_ranges.split("\n")
        }

        with open("node_data.json", "w") as f:
            json.dump(node_data, f)

        print(f"Node data saved to node_data.json:\n{json.dumps(node_data, indent=2)}")
    else:
        print("Failed to fetch metadata. Exiting.")

register_node()