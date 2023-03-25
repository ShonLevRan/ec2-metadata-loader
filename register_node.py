# register_node.py

import os
import json
import boto3
import requests
from requests.exceptions import RequestException
import pyshark
import queue
import threading
import time
from prometheus_client import start_http_server, Counter, Gauge

# Define Prometheus metrics
incoming_bytes = Counter('network_incoming_bytes', 'Total incoming network bytes', ['src', 'dst'])
outgoing_bytes = Counter('network_outgoing_bytes', 'Total outgoing network bytes', ['src', 'dst'])

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

    if node_name and node_ip and availability_zone:
        node_data = {
            "node_name": node_name,
            "node_ip": node_ip, 
            "availability_zone": availability_zone
        }

        with open("node_data.json", "w") as f:
            json.dump(node_data, f)

        print(f"Node data saved to node_data.json:\n{json.dumps(node_data, indent=2)}")
    else:
        print("Failed to fetch metadata. Exiting.")

register_node()

# Configure the interface
interface = ['any']

# Initialize a queue to store captured packets
packet_queue = queue.Queue()

# Thread to continuously capture packets
def packet_capture_thread():
    def packet_handler(packet):
        packet_queue.put(packet)

    capture = pyshark.LiveCapture(interface=interface)
    capture.apply_on_packets(packet_handler)

# Thread to process and aggregate network data every minute
def packet_processing_thread():
    while True:
        start_time = time.time()

        # Initialize data structures to store traffic information
        traffic = {
            'incoming': {},
            'outgoing': {},
        }

        # Process packets in the last minute
        while time.time() - start_time < 5:
            try:
                packet = packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                src = packet.ip.src
                dst = packet.ip.dst
                length = int(packet.length)

                # Determine the direction of the traffic (incoming or outgoing)
                direction = 'outgoing' if src.startswith('10.') or src.startswith('192.168.') else 'incoming'

                # Update traffic information
                pair_key = (src, dst)
                if pair_key not in traffic[direction]:
                    traffic[direction][pair_key] = 0
                traffic[direction][pair_key] += length

                # Update Prometheus metrics
                if direction == 'incoming':
                    incoming_bytes.labels(src=src, dst=dst).inc(length)
                elif direction == 'outgoing':
                    outgoing_bytes.labels(src=src, dst=dst).inc(length)

            except AttributeError:
                # Skip packets without IP information
                continue

        # Create a dictionary object with the traffic information
        traffic_dict = {
            'incoming': [],
            'outgoing': [],
        }

        for (src, dst), bytes_count in traffic['incoming'].items():
            traffic_dict['incoming'].append({
                'src': src,
                'dst': dst,
                'bytes_count': bytes_count
            })

        for (src, dst), bytes_count in traffic['outgoing'].items():
            traffic_dict['outgoing'].append({
                'src': src,
                'dst': dst,
                'bytes_count': bytes_count
            })

        # Serialize the dictionary to a JSON string and print the diff
        json_string = json.dumps(traffic_dict, indent=4)
        print(json_string)

# Start the Prometheus metrics server
start_http_server(8001)

# Start the packet capture and processing threads
capture_thread = threading.Thread(target=packet_capture_thread, daemon=True)
processing_thread = threading.Thread(target=packet_processing_thread, daemon=True)
capture_thread.start()
processing_thread.start()

# Keep the main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass