# capture_traffic.py

import warnings
from scapy.all import sniff
import pandas as pd
from datetime import datetime
import logging

# Suppress specific warnings related to cryptography
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Configure logging
logging.basicConfig(
    filename='capture_traffic.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s:%(message)s'
)

# Define a list to store captured packet data
packets_data = []

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Extracts timestamp, source IP, destination IP, protocol, and length.
    """
    try:
        # Extract packet details
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[1].src if packet.haslayer('IP') else 'N/A'
        dst_ip = packet[1].dst if packet.haslayer('IP') else 'N/A'
        protocol = packet[1].proto if packet.haslayer('IP') else 'N/A'
        length = len(packet)
        
        # Append data to the list
        packets_data.append({
            'Timestamp': timestamp,
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': protocol,
            'Length': length
        })

        # Debugging: Print packet summary
        print(f"Packet captured: {packet.summary()}")
        
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        print(f"Error processing packet: {e}")

def capture_packets(interface='en1', count=100):
    """
    Captures network packets on the specified interface.
    
    Args:
        interface (str): Network interface to monitor (e.g., 'en1', 'en0').
        count (int): Number of packets to capture.
    """
    try:
        print(f"Starting packet capture on {interface} for {count} packets...")
        logging.info(f"Starting packet capture on {interface} for {count} packets...")
        sniff(iface=interface, prn=packet_callback, count=count)
        print("Packet capture completed.")
        logging.info("Packet capture completed.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
        print(f"An error occurred during packet capture: {e}")

def save_to_csv(filename='network_traffic.csv'):
    """
    Saves captured packet data to a CSV file.
    
    Args:
        filename (str): Name of the CSV file.
    """
    try:
        df = pd.DataFrame(packets_data)
        df.to_csv(filename, index=False)
        print(f"Data saved to {filename}")
        logging.info(f"Data saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving data to CSV: {e}")
        print(f"An error occurred while saving data to CSV: {e}")

if __name__ == "__main__":
    try:
        # Customize interface and packet count as needed
        capture_packets(interface='en1', count=100)  # Replace 'en1' with your network interface if different
        save_to_csv('network_traffic.csv')
        print("Packet capture and save successful.")
        logging.info("Packet capture and save successful.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logging.error(f"Script terminated with error: {e}")