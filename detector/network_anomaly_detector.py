# network_anomaly_detector.py
import pickle
import argparse
import sys
import re
import os
import csv
import time
import signal
import platform
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Import necessary Scapy layers
from scapy.all import sniff, rdpcap, Ether, IP, TCP, UDP, ICMP, ARP, IPv6, Packet

# Global variables
BASELINE_DATA = {
    'known_ouis': {},
    'allowed_protocols': set()
}

# Global dictionary to track connection counts
CONNECTION_STATS = defaultdict(int)

# Continuous run control
RUNNING = True
LAST_EXPORT_TIME = time.time()
EXPORT_INTERVAL = 600  # 10 minutes in seconds
OUTPUT_DIR = "anomaly_logs"

# Define relative path to baseline directory
BASELINE_DIR = Path(__file__).resolve().parent.parent / "baseline" / "pickle_files"

# --- Helper Functions ---
def normalize_mac_to_oui(mac_address):
    """Extracts and normalizes the OUI part (first 6 hex digits) from a MAC."""
    if not isinstance(mac_address, str): return None
    cleaned = re.sub(r'[:.\-]', '', mac_address)
    if len(cleaned) >= 6:
        oui_part = cleaned[:6].upper()
        if all(c in '0123456789ABCDEF' for c in oui_part):
            return oui_part
    return None

def get_manufacturer(mac_address):
    """Gets the manufacturer name for a MAC address using the known OUIs database."""
    global BASELINE_DATA
    if not mac_address: return "UNKNOWN"

    oui = normalize_mac_to_oui(mac_address)
    if not oui: return "UNKNOWN"

    # Special case for broadcast/multicast
    if mac_address.lower() == "ff:ff:ff:ff:ff:ff":
        return "BROADCAST"

    # Check if first byte has the multicast bit set (least significant bit of first octet)
    try:
        first_byte = int(mac_address.split(':')[0], 16)
        if (first_byte & 1) == 1:
            return "MULTICAST"
    except (ValueError, IndexError):
        pass

    # Look up in the known OUIs database
    if oui in BASELINE_DATA['known_ouis']:
        return BASELINE_DATA['known_ouis'][oui]

    return "UNKNOWN"

def get_connection_key(packet, protocol):
    """Creates a unique key for a connection to track connection counts."""
    # Extract source and destination information
    src_mac = dst_mac = src_ip = dst_ip = src_port = dst_port = ""

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    if TCP in packet:
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
    elif UDP in packet:
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)

    # Create a connection key that uniquely identifies this flow
    key = f"{protocol}|{src_mac}|{src_ip}|{src_port}|{dst_mac}|{dst_ip}|{dst_port}"
    return key

def load_baseline(baseline_file, expected_key):
    """Loads data from a pickle file and merges it into the global BASELINE_DATA."""
    global BASELINE_DATA
    print(f"Loading baseline file: {baseline_file} (expecting key: '{expected_key}')...")
    try:
        with open(baseline_file, 'rb') as f:
            data = pickle.load(f)

        if not isinstance(data, dict) or expected_key not in data:
            print(f"Error: Baseline file '{baseline_file}' is missing expected key '{expected_key}' or is not a dictionary.", file=sys.stderr)
            return False # Indicate failure

        # Specific validation based on key
        if expected_key == 'known_ouis':
            if not isinstance(data['known_ouis'], dict):
                 print(f"Error: Key 'known_ouis' in '{baseline_file}' should contain a dictionary.", file=sys.stderr)
                 return False
            BASELINE_DATA['known_ouis'].update(data['known_ouis']) # Merge dictionaries
            print(f" - Loaded/Updated {len(data['known_ouis'])} OUI entries. Total known OUIs: {len(BASELINE_DATA['known_ouis'])}")

        elif expected_key == 'allowed_protocols':
            if not isinstance(data['allowed_protocols'], set):
                 print(f"Error: Key 'allowed_protocols' in '{baseline_file}' should contain a set.", file=sys.stderr)
                 return False
            BASELINE_DATA['allowed_protocols'].update(data['allowed_protocols']) # Merge sets
            print(f" - Loaded/Updated {len(data['allowed_protocols'])} protocol entries. Total allowed protocols: {len(BASELINE_DATA['allowed_protocols'])}")

        else:
             print(f"Warning: Unknown expected key '{expected_key}' during loading.", file=sys.stderr)

        return True # Indicate success

    except FileNotFoundError:
        print(f"Error: Baseline file '{baseline_file}' not found.", file=sys.stderr)
        return False
    except pickle.UnpicklingError:
        print(f"Error: Could not unpickle baseline file '{baseline_file}'.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error loading baseline file '{baseline_file}': {e}", file=sys.stderr)
        return False

def get_packet_protocol(packet: Packet) -> str | None:
    """Tries to determine the primary protocol name from a Scapy packet."""
    if ARP in packet:
        return "ARP"
    elif ICMP in packet and IP in packet: # ICMP for IPv4
        return "ICMP"
    elif ICMP in packet and IPv6 in packet: # ICMPv6 Check
         if packet.haslayer(IPv6) and packet[IPv6].nh == 58: # 58 is the protocol number for ICMPv6
             return "IPV6-ICMP"
    elif TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif IPv6 in packet:
        proto_name = packet[IPv6].sprintf("%IPv6.nh%").upper()
        if "ICMP" in proto_name: return "IPV6-ICMP"
        return proto_name if proto_name != "??" else None
    elif IP in packet:
        proto_name = packet[IP].sprintf("%IP.proto%").upper()
        if "ICMP" in proto_name and "V6" in proto_name: return "IPV6-ICMP"
        if "ICMP" in proto_name: return "ICMP"
        return proto_name if proto_name != "??" else None
    elif Ether in packet:
        etype = packet[Ether].type
        if etype == 0x86DD: return "IPV6"
        if etype == 0x88CC: return "LLDP"
    return None

def format_port(port, protocol):
    """Format port numbers for the CSV output, handling ephemeral ports."""
    if not port:
        return ""

    try:
        port_num = int(port)
        # Check if it's an ephemeral port (typically > 1024)
        if port_num > 1024 and protocol in ["TCP", "UDP"]:
            return "EPH"
        return port
    except (ValueError, TypeError):
        return port

def signal_handler(sig, frame):
    """Handle Ctrl+C and other termination signals gracefully."""
    global RUNNING
    print("\nReceived termination signal. Finishing current processing and exporting data...")
    RUNNING = False

def check_and_export_csv():
    """Check if it's time to export the CSV file and do so if needed."""
    global LAST_EXPORT_TIME, CONNECTION_STATS

    current_time = time.time()
    if (current_time - LAST_EXPORT_TIME >= EXPORT_INTERVAL) and CONNECTION_STATS:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(OUTPUT_DIR, f"anomalies_{timestamp}.csv")

        # Write the CSV file
        write_anomalies_to_csv(output_file)

        # Reset the connection stats and update the last export time
        CONNECTION_STATS = defaultdict(int)
        LAST_EXPORT_TIME = current_time

        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Exported anomalies to {output_file} and reset counters.")
        return True

    return False

def write_anomalies_to_csv(output_file):
    """Write the collected anomalies to a CSV file in the specified format."""
    global CONNECTION_STATS

    # If no anomalies were detected, don't create an empty file
    if not CONNECTION_STATS:
        print("No anomalies detected, CSV file not created.")
        return

    print(f"Writing {len(CONNECTION_STATS)} anomalous connections to {output_file}...")

    try:
        with open(output_file, 'w', newline='') as csvfile:
            # Define the CSV header
            fieldnames = ['PROTOCOL', 'SRCMAC', 'SRCMFG', 'SRCIP', 'SRCPORT',
                         'DSTMAC', 'DSTMFG', 'DSTIP', 'DSTPORT', 'CNT']

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Group the connections by their characteristics
            grouped_connections = defaultdict(list)

            for conn_key, count in CONNECTION_STATS.items():
                # Split the connection key back into its components
                parts = conn_key.split('|')
                if len(parts) < 7:
                    continue  # Skip malformed keys

                protocol, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port = parts

                # Get manufacturer information
                src_mfg = get_manufacturer(src_mac)
                dst_mfg = get_manufacturer(dst_mac)

                # Format ports for display
                src_port_formatted = format_port(src_port, protocol)
                dst_port_formatted = format_port(dst_port, protocol)

                # Create a connection group key (without ports for grouping related connections)
                group_key = f"{protocol}:{src_mac}:{dst_mac}:{src_ip}:{dst_ip}"

                # Store the full connection details with the count
                conn_details = {
                    'PROTOCOL': protocol,
                    'SRCMAC': src_mac,
                    'SRCMFG': src_mfg,
                    'SRCIP': src_ip,
                    'SRCPORT': src_port_formatted,
                    'DSTMAC': dst_mac,
                    'DSTMFG': dst_mfg,
                    'DSTIP': dst_ip,
                    'DSTPORT': dst_port_formatted,
                    'CNT': f"{count}.0"  # Format as requested
                }

                grouped_connections[group_key].append(conn_details)

            # Write each group of connections with blank lines between groups
            first_group = True
            for group, connections in grouped_connections.items():
                # Add blank line before groups (except the first one)
                if not first_group:
                    writer.writerow(dict.fromkeys(fieldnames, ''))
                else:
                    first_group = False

                # Write all connections in this group
                for conn in connections:
                    writer.writerow(conn)

        print(f"CSV file written successfully to {output_file}")

    except Exception as e:
        print(f"Error writing CSV file: {e}", file=sys.stderr)


# --- Packet Processing ---
def process_packet_combined_check(packet):
    """
    Processes a single packet, checking its OUI and Protocol against loaded baselines.
    Records anomalies in the global CONNECTION_STATS dictionary.
    """
    global BASELINE_DATA, CONNECTION_STATS, RUNNING

    # Check if we should still be running
    if not RUNNING:
        return

    # Skip processing if no baseline data
    if not BASELINE_DATA or not BASELINE_DATA['known_ouis'] or not BASELINE_DATA['allowed_protocols']:
        if not hasattr(process_packet_combined_check, "warned_no_baseline"):
             print("Warning: Baseline data (OUI or Protocol) is missing or empty. Checks may be ineffective.", file=sys.stderr)
             process_packet_combined_check.warned_no_baseline = True
        return

    known_ouis = BASELINE_DATA['known_ouis']
    allowed_protocols = BASELINE_DATA['allowed_protocols']
    anomaly_found = False

    # --- 1. OUI Check ---
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_oui = normalize_mac_to_oui(src_mac)
        dst_oui = normalize_mac_to_oui(dst_mac)

        # Check Source OUI
        if src_oui and src_oui not in known_ouis:
            anomaly_found = True

        # Check Destination OUI (if unicast)
        if dst_oui:
            is_broadcast = dst_mac == "ff:ff:ff:ff:ff:ff"
            is_multicast = False
            try:
                if (int(dst_oui[:2], 16) & 1) == 1: is_multicast = True
            except ValueError: pass

            if not is_broadcast and not is_multicast and dst_oui not in known_ouis:
                 anomaly_found = True

    # --- 2. Protocol Check ---
    protocol = get_packet_protocol(packet)

    if protocol:
        protocol = protocol.upper()
        if protocol not in allowed_protocols:
            anomaly_found = True
    elif Ether in packet:
        etype = packet[Ether].type
        common_types = {0x0800, 0x0806, 0x86DD}
        if etype not in common_types:
            anomaly_found = True
            protocol = f"UNKNOWN-{hex(etype)}"  # Use a placeholder protocol name for recording

    # Record the connection statistics if we found an anomaly
    if anomaly_found and protocol:
        conn_key = get_connection_key(packet, protocol)
        CONNECTION_STATS[conn_key] += 1

        # Check if it's time to export the CSV
        check_and_export_csv()

def get_platform_specific_filter():
    """Returns the appropriate packet filter for the current platform."""
    system = platform.system().lower()

    # Different platforms might need different filter expressions
    if system == "darwin":  # macOS
        # On macOS, simple filter expressions work better
        return ""  # Empty string means no filter - capture all packets
    elif system == "linux":
        # On Linux, 'ether' is widely supported
        return "ether"
    elif system == "windows":
        # On Windows, specific filters depend on the capture library
        # Empty filter is safer but less efficient
        return ""
    else:
        # Default to empty filter for unknown platforms
        return ""

# --- Main Execution ---
def main():
    global EXPORT_INTERVAL, OUTPUT_DIR, RUNNING, LAST_EXPORT_TIME

    parser = argparse.ArgumentParser(description="Cross-Platform Network Anomaly Detector - Exports anomalies every 10 minutes")

    # Default paths calculated relative to the script location
    default_oui_baseline = BASELINE_DIR / "oui_baseline.pkl"
    default_protocol_baseline = BASELINE_DIR / "protocol_baseline.pkl"

    parser.add_argument("-ob", "--oui-baseline", default=str(default_oui_baseline),
                        help=f"Path to the OUI baseline pickle file (default: {default_oui_baseline}).")
    parser.add_argument("-pb", "--protocol-baseline", default=str(default_protocol_baseline),
                        help=f"Path to the Protocol baseline pickle file (default: {default_protocol_baseline}).")
    parser.add_argument("-i", "--iface", required=True,
                        help="Network interface name to sniff live traffic (e.g., eth0/en0/wlan0).")
    parser.add_argument("-o", "--output-dir", default=OUTPUT_DIR,
                        help=f"Directory to save the CSV output files (default: {OUTPUT_DIR}).")
    parser.add_argument("-t", "--interval", type=int, default=int(EXPORT_INTERVAL/60),
                        help=f"Interval in minutes between CSV exports (default: {int(EXPORT_INTERVAL/60)}).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output (prints all anomalies in real-time)")
    parser.add_argument("-f", "--filter",
                        help="Custom BPF filter to apply (overrides platform-specific defaults)")

    args = parser.parse_args()

    # Determine the operating system for platform-specific behaviors
    system = platform.system()
    print(f"Detected operating system: {system}")

    # Update global settings based on arguments
    OUTPUT_DIR = args.output_dir
    EXPORT_INTERVAL = args.interval * 60  # Convert minutes to seconds

    # Create output directory if it doesn't exist
    if not os.path.exists(OUTPUT_DIR):
        try:
            os.makedirs(OUTPUT_DIR)
            print(f"Created output directory: {OUTPUT_DIR}")
        except Exception as e:
            print(f"Error creating output directory: {e}", file=sys.stderr)
            sys.exit(1)

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"""
====================================
=     NETWORK ANOMALY DETECTOR     =
====================================
""")
    print(f"CSV files will be saved to: {OUTPUT_DIR}")
    print(f"Export interval: {args.interval} minutes")
    print(f"Sniffing on interface: {args.iface}")

    # Check if the baseline files exist
    oui_baseline_path = args.oui_baseline
    protocol_baseline_path = args.protocol_baseline

    if not os.path.exists(oui_baseline_path):
        print(f"Error: OUI baseline file not found at {oui_baseline_path}", file=sys.stderr)
        print(f"Make sure you've run the baseline creation scripts in the baseline directory.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(protocol_baseline_path):
        print(f"Error: Protocol baseline file not found at {protocol_baseline_path}", file=sys.stderr)
        print(f"Make sure you've run the baseline creation scripts in the baseline directory.", file=sys.stderr)
        sys.exit(1)

    # Load both baselines
    oui_loaded = load_baseline(oui_baseline_path, 'known_ouis')
    protocol_loaded = load_baseline(protocol_baseline_path, 'allowed_protocols')

    # Exit if mandatory baselines failed to load
    if not oui_loaded or not protocol_loaded:
         print("\nCritical baseline loading failed. Exiting.", file=sys.stderr)
         sys.exit(1)
    elif not BASELINE_DATA['known_ouis'] and not BASELINE_DATA['allowed_protocols']:
         print("\nWarning: Both OUI and Protocol baselines are empty. Detector may not be effective.", file=sys.stderr)
         # Continue running, but user should be aware.

    # Initialize the last export time
    LAST_EXPORT_TIME = time.time()

    # Determine which packet filter to use (platform-specific or user-provided)
    packet_filter = args.filter if args.filter else get_platform_specific_filter()
    if packet_filter:
        print(f"Using packet filter: '{packet_filter}'")
    else:
        print("No packet filter applied - capturing all packets")

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting continuous packet capture...")
    print("Press Ctrl+C to stop the detector and save final results.")

    try:
        # Start continuous sniffing - note the store=0 which is important for memory efficiency in 24/7 operation
        while RUNNING:
            try:
                # Capture packets in smaller batches to allow for periodic CSV exports
                # Use filter only if one is specified (to avoid filter errors on some platforms)
                if packet_filter:
                    sniff(iface=args.iface, filter=packet_filter, prn=process_packet_combined_check,
                          count=1000, store=0, timeout=60)
                else:
                    sniff(iface=args.iface, prn=process_packet_combined_check,
                          count=1000, store=0, timeout=60)

                # Check if we should export even if we didn't hit any anomalies during sniffing
                if time.time() - LAST_EXPORT_TIME >= EXPORT_INTERVAL and CONNECTION_STATS:
                    check_and_export_csv()

            except Exception as e:
                print(f"Error during packet capture: {e}", file=sys.stderr)
                # Don't exit, try to continue capturing after a short delay
                time.sleep(5)

        # Final export when shutting down
        if CONNECTION_STATS:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(OUTPUT_DIR, f"anomalies_final_{timestamp}.csv")
            write_anomalies_to_csv(output_file)
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Final export completed to {output_file}")

    except KeyboardInterrupt:
        print("\nDetector stopped by user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
    finally:
        print("\nDetector shutdown complete.")

if __name__ == "__main__":
    main()

# --- How to run ---
# 1. Make sure baseline files are created:
#    cd ../baseline
#    python create_oui_baseline.py
#    python create_protocol_baseline.py
#
# 2. Run the cross-platform detector (might need admin privileges):
#
#    # On Linux:
#    sudo python cross_platform_anomaly_detector.py -i eth0
#
#    # On macOS:
#    sudo python cross_platform_anomaly_detector.py -i en0
#
#    # On Windows (run cmd as administrator):
#    python cross_platform_anomaly_detector.py -i Ethernet
#
# 3. To change the export interval (e.g., to 5 minutes):
#    sudo python cross_platform_anomaly_detector.py -i en0 -t 5
#
# 4. To specify a different output directory:
#    sudo python cross_platform_anomaly_detector.py -i en0 -o /path/to/log/directory
#
# 5. To use a custom packet filter (advanced users):
#    sudo python cross_platform_anomaly_detector.py -i en0 -f "ip or ip6"
