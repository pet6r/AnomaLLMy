#!/usr/bin/env python3
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

# --- Global Variables ---
# For Anomaly Detection (Whitelist)
BASELINE_DATA = {
    'known_ouis': {},
    'allowed_protocols': set()
}

# For Manufacturer Name Lookup (Comprehensive List)
COMPREHENSIVE_OUI_LOOKUP = {}

# For Tracking Anomalies
CONNECTION_STATS = defaultdict(int)

# Control Variables
RUNNING = True
LAST_EXPORT_TIME = time.time()
EXPORT_INTERVAL = 600  # 10 minutes in seconds
OUTPUT_DIR = "anomaly_logs"
FORCE_EXPORT = False   # Flag to force export even if no anomalies

# Define relative path to baseline directory
# Assumes baseline/pickle_files is two levels up from the script's directory
BASELINE_DIR = Path(__file__).resolve().parent.parent / "baseline" / "pickle_files"
# Default path for the comprehensive OUI file
DEFAULT_COMPREHENSIVE_OUI_PATH = BASELINE_DIR / "oui_comprehensive.pkl"


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

# <<< MODIFIED get_manufacturer >>>
def get_manufacturer(mac_address):
    """
    Gets the manufacturer name for a MAC address using the
    COMPREHENSIVE OUI lookup dictionary.
    """
    global COMPREHENSIVE_OUI_LOOKUP # Use the comprehensive list

    if not mac_address: return "UNKNOWN"

    oui = normalize_mac_to_oui(mac_address)
    if not oui: return "UNKNOWN"

    # Special case for broadcast/multicast (handled before lookup)
    mac_lower = mac_address.lower()
    if mac_lower == "ff:ff:ff:ff:ff:ff":
        return "BROADCAST"
    try:
        first_byte = int(mac_address.split(':')[0], 16)
        if (first_byte & 1) == 1:
            return "MULTICAST"
    except (ValueError, IndexError):
        pass # Ignore malformed MACs for multicast check

    # Look up in the COMPREHENSIVE OUIs database
    return COMPREHENSIVE_OUI_LOOKUP.get(oui, "UNKNOWN") # Use .get for safety

def get_connection_key(packet, protocol):
    """Creates a unique key for a connection to track connection counts."""
    # Extract source and destination information
    src_mac = dst_mac = src_ip = dst_ip = src_port = dst_port = ""

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    # Handle IPv4 and IPv6 for IP addresses
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif ARP in packet: # Get IPs from ARP if available
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst


    if TCP in packet:
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
    elif UDP in packet:
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)

    # Create a connection key that uniquely identifies this flow
    # Using consistent placeholders for missing elements if needed
    key = f"{protocol}|{src_mac or 'N/A'}|{src_ip or 'N/A'}|{src_port or 'N/A'}|{dst_mac or 'N/A'}|{dst_ip or 'N/A'}|{dst_port or 'N/A'}"
    return key

# <<< REVISED load_baseline >>>
def load_baseline(baseline_file, expected_key):
    """
    Loads data from a WHITELIST baseline pickle file (OUI or Protocol)
    and merges it into the global BASELINE_DATA.
    Returns True on success, False on failure.
    """
    global BASELINE_DATA
    # Determine descriptive name based on the key
    baseline_type = "Unknown"
    if expected_key == 'known_ouis':
        baseline_type = "Known Device OUI Whitelist"
    elif expected_key == 'allowed_protocols':
        baseline_type = "Allowed Protocol Whitelist"

    print(f"Loading {baseline_type}: {baseline_file} (key: '{expected_key}')...") # Use descriptive name
    try:
        with open(baseline_file, 'rb') as f:
            data = pickle.load(f)

        # Allow loading direct dict/set or nested structure
        data_to_load = None
        if isinstance(data, dict) and expected_key in data:
             data_to_load = data[expected_key]
        elif expected_key == 'known_ouis' and isinstance(data, dict):
             data_to_load = data
        elif expected_key == 'allowed_protocols' and isinstance(data, set):
             data_to_load = data

        if data_to_load is None:
            print(f"Error: Whitelist file '{baseline_file}' has unexpected format or missing key '{expected_key}'.", file=sys.stderr)
            return False

        # Specific validation and update based on key
        if expected_key == 'known_ouis':
            if not isinstance(data_to_load, dict):
                 print(f"Error: Data for 'known_ouis' in '{baseline_file}' is not a dictionary.", file=sys.stderr)
                 return False
            BASELINE_DATA['known_ouis'].update(data_to_load)
            # Updated print statement for clarity
            print(f" - Loaded/Updated {len(data_to_load)} OUI entries. Total known Whitelist OUIs: {len(BASELINE_DATA['known_ouis'])}")

        elif expected_key == 'allowed_protocols':
            if not isinstance(data_to_load, set):
                 print(f"Error: Data for 'allowed_protocols' in '{baseline_file}' is not a set.", file=sys.stderr)
                 return False
            BASELINE_DATA['allowed_protocols'].update(data_to_load)
            # Updated print statement for clarity
            print(f" - Loaded/Updated {len(data_to_load)} protocol entries. Total Allowed Protocols: {len(BASELINE_DATA['allowed_protocols'])}")
        else:
             print(f"Warning: Unknown expected key '{expected_key}' during baseline loading.", file=sys.stderr)

        return True # Indicate success

    except FileNotFoundError:
        print(f"Error: Whitelist file '{baseline_file}' not found.", file=sys.stderr)
        return False
    except pickle.UnpicklingError:
        print(f"Error: Could not unpickle Whitelist file '{baseline_file}'.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error loading Whitelist file '{baseline_file}': {e}", file=sys.stderr)
        return False

def get_packet_protocol(packet: Packet) -> str | None:
    """Tries to determine the primary protocol name from a Scapy packet."""

    # Order matters: Check more specific layers first
    if TCP in packet: return "TCP"
    if UDP in packet: return "UDP"

    # Check ICMP variations after TCP/UDP
    if ICMP in packet and IPv6 in packet: return "IPV6-ICMP" # Check if ICMP is carried by IPv6
    if ICMP in packet: return "ICMP" # Assume IPv4 if not IPv6
    if ARP in packet: return "ARP"

    # Less common protocols / Layer 2/3 identification
    if IPv6 in packet: return packet[IPv6].sprintf("%IPv6.nh%").upper() # Next header field
    if IP in packet: return packet[IP].sprintf("%IP.proto%").upper() # Protocol field
    if Ether in packet: # Identify some common EtherTypes if no IP layer found
        etype = packet[Ether].type
        if etype == 0x86DD: return "IPV6" # EtherType for IPv6
        if etype == 0x88CC: return "LLDP"

        # Add others if needed, e.g., 0x88A8 (Provider Bridging), 0x8100 (VLAN)
        return f"ETH-{hex(etype)}" # Generic EtherType
    return None # Cannot determine protocol

def format_port(port, protocol):
    """Format port numbers for the CSV output, handling ephemeral ports."""

    if not port or protocol not in ["TCP", "UDP"]: # Only format ports for TCP/UDP
        return ""
    try:
        port_num = int(port)

        # Use IANA suggested ephemeral range (adjust if needed)
        if port_num > 49151:
            return "EPH"
        # Or optionally treat > 1024 as ephemeral
        # if port_num > 1024:
        #     return "EPH"
        return str(port_num) # Return as string if not ephemeral
    except (ValueError, TypeError):
        return str(port) # Return original if conversion fails

def signal_handler(sig, frame):
    """Handle Ctrl+C and other termination signals gracefully."""
    global RUNNING, FORCE_EXPORT
    if RUNNING: # Prevent multiple prints if signal received quickly
        print("\n[!] Termination signal received. Stopping capture and exporting final data...", file=sys.stderr)
        RUNNING = False
        FORCE_EXPORT = True # Ensure final export happens

def check_and_export_csv():
    """Check if it's time to export the CSV file and do so if needed."""
    global LAST_EXPORT_TIME, CONNECTION_STATS, FORCE_EXPORT, OUTPUT_DIR # Ensure OUTPUT_DIR is global

    current_time = time.time()
    # Export if it's time AND there are anomalies, OR if export is forced by signal
    should_export = ((current_time - LAST_EXPORT_TIME >= EXPORT_INTERVAL) and CONNECTION_STATS) or FORCE_EXPORT

    if should_export:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Ensure OUTPUT_DIR is treated as a Path object for consistency if needed elsewhere
        # Or convert to string here
        output_file = os.path.join(str(OUTPUT_DIR), f"anomalies_{timestamp}.csv")

        if CONNECTION_STATS:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Exporting {len(CONNECTION_STATS)} anomalies to {output_file}...")
            write_anomalies_to_csv(output_file) # Call the writer function
        elif FORCE_EXPORT: # Only print "no anomalies" if forced export had nothing
             print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Shutdown initiated, no anomalies detected in the final interval.")
        else: # Standard interval check found nothing
             print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No anomalies detected during this interval.")

        # Reset stats and timer ONLY if export happened (or was supposed to)
        CONNECTION_STATS = defaultdict(int)
        LAST_EXPORT_TIME = current_time
        FORCE_EXPORT = False # Reset force flag after attempting export

        return True # Indicate export was attempted

    return False # Indicate no export occurred


def write_anomalies_to_csv(output_file):
    """
    Write the collected anomalies to a CSV file, grouped by connection endpoints
    (ignoring ports for grouping) and separated by newlines.
    Uses the COMPREHENSIVE OUI list to get manufacturer names.
    """
    global CONNECTION_STATS

    if not CONNECTION_STATS:
        # No print here, handled by check_and_export_csv
        return

    # Use a temporary dictionary to group connections by endpoint (ignoring ports)
    grouped_connections = defaultdict(list)
    fieldnames = ['PROTOCOL', 'SRCMAC', 'SRCMFG', 'SRCIP', 'SRCPORT',
                  'DSTMAC', 'DSTMFG', 'DSTIP', 'DSTPORT', 'CNT']

    # --- Step 1: Group connections by endpoint ---
    for conn_key, count in CONNECTION_STATS.items():
        parts = conn_key.split('|')
        if len(parts) != 7:
            print(f"Warning: Skipping malformed connection key in CSV grouping: {conn_key}", file=sys.stderr)
            continue

        protocol, src_mac, src_ip, src_port_raw, dst_mac, dst_ip, dst_port_raw = parts

        # Create the key for grouping (excludes ports)
        group_key = f"{protocol}|{src_mac}|{src_ip}|{dst_mac}|{dst_ip}"

        # Get manufacturer information using the COMPREHENSIVE lookup
        src_mfg = get_manufacturer(src_mac if src_mac != 'N/A' else None)
        dst_mfg = get_manufacturer(dst_mac if dst_mac != 'N/A' else None)

        # Format ports for display
        src_port_formatted = format_port(src_port_raw if src_port_raw != 'N/A' else None, protocol)
        dst_port_formatted = format_port(dst_port_raw if dst_port_raw != 'N/A' else None, protocol)

        # Store the full connection details needed for the final row
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
            'CNT': f"{count}.0" # Format count as requested
        }
        # Append the details to the list associated with the group key
        grouped_connections[group_key].append(conn_details)

    # --- Step 2: Write the grouped connections to CSV with separators ---
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            first_group = True
            # Iterate through the groups we created
            for group_key, connections_in_group in grouped_connections.items():
                # Add blank line separator before each group (except the first)
                if not first_group:
                    # Create an empty row dictionary matching fieldnames
                    writer.writerow(dict.fromkeys(fieldnames, ''))
                else:
                    first_group = False

                # Write all connections belonging to this group
                for conn_detail_row in connections_in_group:
                    writer.writerow(conn_detail_row)

        # Success message moved to check_and_export_csv for better flow

    except Exception as e:
        print(f"Error writing grouped CSV file '{output_file}': {e}", file=sys.stderr)


# --- Packet Processing ---
def process_packet_combined_check(packet):
    """
    Processes a single packet, checking its OUI and Protocol against ANOMALY baselines.
    Records anomalies in the global CONNECTION_STATS dictionary.
    Does NOT use the comprehensive OUI list for anomaly check.
    """
    global BASELINE_DATA, CONNECTION_STATS, RUNNING

    if not RUNNING: return # Check if shutdown signal received

    # Use baseline data loaded previously for checks
    # Ensure keys exist before accessing
    known_ouis = BASELINE_DATA.get('known_ouis', {})
    allowed_protocols = BASELINE_DATA.get('allowed_protocols', set())

    # Skip if baselines are empty (optional, prevents useless checks)
    # if not known_ouis and not allowed_protocols:
    #      return

    anomaly_found = False
    protocol = get_packet_protocol(packet) # Determine protocol early

    # --- 1. OUI Check (using ANOMALY baseline) ---
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_oui = normalize_mac_to_oui(src_mac)
        dst_oui = normalize_mac_to_oui(dst_mac)

        # Check Source OUI against ANOMALY baseline
        if src_oui and src_oui not in known_ouis:
            anomaly_found = True

        # Check Destination OUI against ANOMALY baseline (if unicast)
        if dst_oui:
            is_broadcast = dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
            is_multicast = False
            try: # Check multicast bit
                if not is_broadcast and (int(dst_oui[:2], 16) & 1) == 1: is_multicast = True
            except ValueError: pass

            if not is_broadcast and not is_multicast and dst_oui not in known_ouis:
                 anomaly_found = True

    # --- 2. Protocol Check (using ANOMALY baseline) ---
    if protocol:
        protocol_upper = protocol.upper() # Compare uppercase
        if protocol_upper not in allowed_protocols:
            anomaly_found = True
    # Optional: Consider handling packets where protocol couldn't be determined
    # elif Ether in packet: # Example: Flag unknown EtherTypes
    #     etype = packet[Ether].type
    #     # Define known/expected EtherTypes if needed
    #     known_etypes = {0x0800, 0x0806, 0x86DD, 0x8100, 0x88A8, 0x88CC}
    #     if etype not in known_etypes:
    #         anomaly_found = True
    #         protocol = f"ETH-{hex(etype)}" # Use placeholder if protocol is None

    # --- Record Anomaly ---
    # Record if an anomaly was found AND we could determine a protocol name
    if anomaly_found and protocol:
        conn_key = get_connection_key(packet, protocol)
        CONNECTION_STATS[conn_key] += 1


def get_platform_specific_filter():
    """Returns a suggested default packet filter (can be empty)."""
    # Keep it simple, empty filter captures most things Scapy can parse.
    # Specific filters ("tcp or udp...") might miss things or cause issues.
    # User can override with -f if needed.
    print("Using empty default filter (captures common layers). Override with -f if needed.")
    return ""

# --- Main Execution ---
def main():
    # Make sure all accessed globals are declared if modified
    global EXPORT_INTERVAL, OUTPUT_DIR, RUNNING, LAST_EXPORT_TIME, BASELINE_DATA, COMPREHENSIVE_OUI_LOOKUP, CONNECTION_STATS

    parser = argparse.ArgumentParser(
        description="Continuous Network Anomaly Detector using Scapy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )

    # --- Argument Parsing ---
    default_oui_baseline = BASELINE_DIR / "oui_baseline.pkl"
    default_protocol_baseline = BASELINE_DIR / "protocol_baseline.pkl"
    # Use the constant defined earlier for the comprehensive default path
    default_comp_oui_path = DEFAULT_COMPREHENSIVE_OUI_PATH

    # Anomaly Detection Baselines
    parser.add_argument("-ob", "--oui-baseline", default=str(default_oui_baseline),
                        help="Path to the OUI baseline pickle file (for ANOMALY detection).")
    parser.add_argument("-pb", "--protocol-baseline", default=str(default_protocol_baseline),
                        help="Path to the Protocol baseline pickle file (for ANOMALY detection).")
    # Comprehensive Lookup Baseline
    parser.add_argument("-cb", "--comprehensive-baseline", default=str(default_comp_oui_path),
                        help="Path to the COMPREHENSIVE OUI pickle file (for manufacturer name lookup).")
    # Required arguments
    parser.add_argument("-i", "--iface", required=True,
                        help="Network interface name for live capture (e.g., eth0, en0).")
    # Optional arguments
    parser.add_argument("-o", "--output-dir", default=OUTPUT_DIR,
                        help="Directory to save the anomaly CSV output files.")
    parser.add_argument("-t", "--interval", type=int, default=int(EXPORT_INTERVAL/60),
                        help="Interval in minutes between CSV exports.")
    parser.add_argument("-f", "--filter", default="", # Default to empty string filter
                        help="Custom BPF filter (e.g., 'tcp port 80'). Overrides platform defaults.")
    parser.add_argument("-v", "--verbose", action="store_true", # Currently unused, add logic if needed
                        help="Enable verbose output during operation.")

    args = parser.parse_args()

    # --- Initialization ---
    print(f"Detected operating system: {platform.system()}")
    OUTPUT_DIR = Path(args.output_dir) # Use Path object for directory
    EXPORT_INTERVAL = args.interval * 60
    if EXPORT_INTERVAL <= 0:
         print("Warning: Export interval must be positive. Using default (10 minutes).", file=sys.stderr)
         EXPORT_INTERVAL = 600

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {OUTPUT_DIR.resolve()}")
    except Exception as e:
        print(f"Error creating output directory '{OUTPUT_DIR}': {e}", file=sys.stderr)
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"""
=======================================
= CONTINUOUS NETWORK ANOMALY DETECTOR =
=======================================
""")
    print(f"Anomaly CSVs will be saved to: {OUTPUT_DIR}")
    print(f"Export interval: {args.interval} minutes")
    print(f"Sniffing on interface: {args.iface}")

    # --- Load Baselines ---
    # Load Anomaly Baselines
    oui_loaded = load_baseline(args.oui_baseline, 'known_ouis')
    protocol_loaded = load_baseline(args.protocol_baseline, 'allowed_protocols')

    # Load Comprehensive OUI Lookup File
    comp_oui_loaded = False
    comp_oui_path = Path(args.comprehensive_baseline)
    print(f"Loading COMPREHENSIVE OUI lookup: {comp_oui_path}...")
    if comp_oui_path.exists():
        try:
            with open(comp_oui_path, 'rb') as f:
                loaded_data = pickle.load(f)
            if isinstance(loaded_data, dict):
                COMPREHENSIVE_OUI_LOOKUP = loaded_data
                print(f" - Loaded {len(COMPREHENSIVE_OUI_LOOKUP)} COMPREHENSIVE OUI entries.")
                comp_oui_loaded = True
            else:
                print(f"Error: Comprehensive OUI file '{comp_oui_path}' did not contain a dictionary.", file=sys.stderr)
        except pickle.UnpicklingError:
             print(f"Error: Could not unpickle comprehensive OUI file '{comp_oui_path}'.", file=sys.stderr)
        except Exception as e:
             print(f"Error loading comprehensive OUI file '{comp_oui_path}': {e}", file=sys.stderr)
    else:
        print(f"Warning: Comprehensive OUI file '{comp_oui_path}' not found.", file=sys.stderr)

    if not comp_oui_loaded:
         print("Warning: Comprehensive OUI lookup failed. Manufacturer names will be 'UNKNOWN'.", file=sys.stderr)
         # Continue running, but MFG names won't work.

    # Check if critical anomaly baselines failed (optional stricter check)
    if not oui_loaded or not protocol_loaded:
         print("\nWarning: Anomaly baseline loading failed or incomplete. Detection may be unreliable.", file=sys.stderr)
         sys.exit(1)


    # --- Start Capture ---
    LAST_EXPORT_TIME = time.time() # Initialize export timer
    packet_filter = args.filter # Use user filter directly, empty if not provided

    if packet_filter:
        print(f"Using packet filter: '{packet_filter}'")
    else:
        print("No specific packet filter applied (capturing common layers).")

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting continuous packet capture...")
    print("Press Ctrl+C to stop.")

    last_status_time = time.time()
    status_interval = 300 # Print status every 5 minutes

    try:
        while RUNNING:
            current_time = time.time()
            # --- Periodic Actions ---
            # 1. Check for export interval
            check_and_export_csv() # Checks time and CONNECTION_STATS

            # 2. Print status update
            if current_time - last_status_time >= status_interval:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Monitoring... ({len(CONNECTION_STATS)} anomalies queued for next export)")
                last_status_time = current_time

            # --- Sniffing ---
            # Sniff for a short duration to allow periodic checks to run
            # Reduce count/timeout further if needed for faster response to Ctrl+C
            sniff(iface=args.iface,
                  filter=packet_filter,
                  prn=process_packet_combined_check,
                  store=0, # Don't store packets in memory
                  timeout=10, # Sniff for 10 seconds
                  count=0) # Capture indefinitely within the timeout
                  # stop_filter=lambda x: not RUNNING) # Optional: check RUNNING more often

            # Add a tiny sleep to prevent high CPU usage in case sniff returns immediately
            # time.sleep(0.01)

    except PermissionError:
        print(f"\n[!] Permission Error: Failed to capture on {args.iface}.", file=sys.stderr)
        print( "   Please run the script with sufficient privileges (e.g., using 'sudo').")
        sys.exit(1)
    except OSError as e:
        # Catch specific OSError for interface issues
        print(f"\n[!] Network Interface Error: {e}", file=sys.stderr)
        print(f"    Could not capture on interface '{args.iface}'. Check name, status, and privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        # Should be caught by signal handler, but as a fallback
        print("\nKeyboardInterrupt detected.")
        if RUNNING: # If signal handler didn't run first
            signal_handler(signal.SIGINT, None) # Manually trigger shutdown logic
    except Exception as e:
        print(f"\n[!] An unexpected error occurred in the main loop: {e}", file=sys.stderr)
    finally:
        # --- Final Export on Shutdown ---
        print("\nInitiating shutdown...")
        # Force one last check/export cycle using the flag
        FORCE_EXPORT = True
        check_and_export_csv()
        print("Detector shutdown complete.")

if __name__ == "__main__":
    # Optional privilege check (basic)
    if '-i' in sys.argv or '--iface' in sys.argv:
        try:
            is_admin = (os.geteuid() == 0) if hasattr(os, 'geteuid') else (ctypes.windll.shell32.IsUserAnAdmin() != 0)
            if not is_admin:
                print("Warning: Live capture usually requires root/administrator privileges.", file=sys.stderr)
        except NameError: # Handle case where ctypes is not available/imported
            try: # Check geteuid again just in case
                 if hasattr(os, 'geteuid') and os.geteuid() != 0:
                     print("Warning: Live capture usually requires root/administrator privileges.", file=sys.stderr)
            except AttributeError: # If geteuid also doesn't exist
                 print("Warning: Could not determine privilege level. Live capture might require root/admin rights.", file=sys.stderr)
        except Exception as e: # Catch other potential errors during check
             print(f"Warning: Could not check privilege level ({e}). Live capture might require root/admin rights.", file=sys.stderr)
             # Import ctypes only needed for Windows check
             import ctypes


    main()
    # --- How to run ---
    # 1. Make sure baseline files are created:
    #    cd ../baseline
    #    python create_oui_baseline.py
    #    python create_protocol_baseline.py
    #
    # 2. Run the network anomaly detector (will need admin privileges):
    #
    #    # On Linux:
    #    sudo python3 network_anomaly_detector.py -i eth0
    #
    #    # On macOS:
    #    sudo python network_anomaly_detector.py -i en0
    #
    #    # On Windows (run cmd as administrator):
    #    python network_anomaly_detector.py -i Ethernet
    #
    # 3. To change the export interval (e.g., to 5 minutes):
    #    sudo python3 network_anomaly_detector.py -i en0 -t 5
    #
    # 4. To specify a different output directory:
    #    sudo python3 network_anomaly_detector.py -i en0 -o /path/to/log/directory
    #
    # 5. To use a custom packet filter (advanced users):
    #    sudo python3 network_anomaly_detector.py -i en0 -f "ip or ip6"
