#!/usr/bin/env python3
# pcap_enhanced_anomaly_detector.py - Enhanced anomaly detector with OUI lookup

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

# For PCAP processing (reading files)
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp
# from pcapfile.protocols.application import arp # pcapfile might not have direct ARP parsing easily accessible
from binascii import unhexlify

# Import necessary Scapy layers for live capture
try:
    from scapy.all import sniff, rdpcap, Ether, IP, TCP, UDP, ICMP, ARP, IPv6, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available. Live capture functionality disabled.")

# --- Global Variables ---
BASELINE_DATA = {
    'known_ouis': {},
    'allowed_protocols': set()
}
CONNECTION_STATS = defaultdict(int) # Stores counts ONLY for anomalous connections
RUNNING = True
LAST_EXPORT_TIME = time.time()
EXPORT_INTERVAL = 600  # Default 10 minutes
OUTPUT_DIR = "anomaly_logs"
# Define relative path to baseline directory
# Assumes baseline/pickle_files is one level up from where the script is
BASELINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "baseline", "pickle_files")

# --- MAC OUI Lookup Class ---
class MAC:
    ''' OUI TRANSLATION MAC TO MFG'''
    def __init__(self, oui_file=None):
        # Prioritize globally loaded baseline data if available
        if BASELINE_DATA['known_ouis']:
            self.macDict = BASELINE_DATA['known_ouis']
            self.has_data = True
            # print("MAC class initialized using pre-loaded baseline OUI data") # Less verbose
            return

        # Fallback to loading from file if baseline wasn't pre-loaded
        if oui_file is None:
            oui_file = os.path.join(BASELINE_DIR, "oui_baseline.pkl")

        if not os.path.exists(oui_file):
            print(f"Warning: OUI file not found at {oui_file}. Manufacturer lookup disabled.", file=sys.stderr)
            self.has_data = False
            self.macDict = {}
            return

        try:
            with open(oui_file, 'rb') as pickleFile:
                loaded_data = pickle.load(pickleFile)
                # Adapt based on expected pickle format (adjust if your format differs)
                if isinstance(loaded_data, dict) and 'known_ouis' in loaded_data:
                    self.macDict = loaded_data['known_ouis']
                    print(f"MAC class loaded {len(self.macDict)} OUI entries from baseline format: {oui_file}")
                elif isinstance(loaded_data, dict): # Assume it's just the dict OUI:MFG
                     self.macDict = loaded_data
                     print(f"MAC class loaded {len(self.macDict)} OUI entries from direct dict format: {oui_file}")
                else:
                    print(f"Warning: Unknown OUI pickle format in {oui_file}. Manufacturer lookup disabled.", file=sys.stderr)
                    self.macDict = {}

                self.has_data = len(self.macDict) > 0
        except Exception as e:
            print(f"Error loading OUI file {oui_file}: {e}", file=sys.stderr)
            self.has_data = False
            self.macDict = {}

    def lookup(self, macAddress):
        """Lookup manufacturer from MAC address prefix"""
        if not self.has_data or not isinstance(macAddress, str):
            return "UNKNOWN"

        # Handle broadcast/multicast explicitly first (optional but good practice)
        if macAddress.lower() == "ff:ff:ff:ff:ff:ff": return "BROADCAST"
        try:
            first_byte = int(macAddress.split(':')[0], 16)
            if (first_byte & 1) == 1: return "MULTICAST" # Check multicast bit
        except (ValueError, IndexError): pass # Ignore malformed MACs

        # Normalize MAC to OUI prefix
        macPrefix = re.sub(r'[:.\-]', '', macAddress)[:6].upper()
        if len(macPrefix) != 6: return "UNKNOWN" # Ensure we have a 6-char prefix

        try:
            return self.macDict.get(macPrefix, "UNKNOWN") # Use dict.get for safety
        except Exception: # Should not happen with .get, but for safety
            return "UNKNOWN"

# --- Helper Functions ---
def normalize_mac_to_oui(mac_address):
    """Extracts and normalizes the OUI part (first 6 hex digits) from a MAC."""
    if not isinstance(mac_address, str): return None
    cleaned = re.sub(r'[:.\-]', '', mac_address)
    if len(cleaned) >= 6:
        oui_part = cleaned[:6].upper()
        # Basic validation
        if all(c in '0123456789ABCDEF' for c in oui_part):
            return oui_part
    return None

def get_manufacturer(mac_address, mac_lookup_obj=None):
    """Gets the manufacturer name for a MAC address using provided object or global baseline."""
    global BASELINE_DATA

    if not mac_address: return "UNKNOWN"

    # Use MAC lookup object if provided (preferred)
    if mac_lookup_obj and mac_lookup_obj.has_data:
        return mac_lookup_obj.lookup(mac_address)

    # Fallback to global baseline data if no object or object has no data
    # Handle broadcast/multicast
    if mac_address.lower() == "ff:ff:ff:ff:ff:ff": return "BROADCAST"
    try:
        first_byte = int(mac_address.split(':')[0], 16)
        if (first_byte & 1) == 1: return "MULTICAST"
    except (ValueError, IndexError): pass

    oui = normalize_mac_to_oui(mac_address)
    if oui and oui in BASELINE_DATA['known_ouis']:
        return BASELINE_DATA['known_ouis'][oui]

    return "UNKNOWN"

def format_port(port, protocol):
    """Format port numbers for the CSV output, handling ephemeral ports."""
    if not port: return ""
    try:
        port_num = int(port)
        # Check if it's an ephemeral port (common range, adjust if needed)
        if port_num > 49151 and protocol in ["TCP", "UDP"]: # IANA suggested range
             return "EPH"
        # Treat 1025-49151 as potentially non-ephemeral for more visibility
        # if port_num > 1024 and protocol in ["TCP", "UDP"]:
        #     return "EPH"
        return str(port_num) # Ensure it's a string
    except (ValueError, TypeError):
        return str(port) # Return original if not an int


# --- PCAP Processing Function ---
def process_pcap_file(pcap_file, output_file=None, verbose=False):
    """Process a PCAP file and generate anomaly report based on baselines."""
    print(f"Processing PCAP file: {pcap_file}")

    global CONNECTION_STATS, BASELINE_DATA
    CONNECTION_STATS = defaultdict(int) # Reset stats for this file

    macOBJ = MAC() # Use MAC class for lookups in this context
    if not macOBJ.has_data:
        print("Warning: OUI lookup data not available for PCAP processing.", file=sys.stderr)

    anomalies_found_in_file = 0
    try:
        with open(pcap_file, 'rb') as pcapCapture:
            capture = savefile.load_savefile(pcapCapture, layers=0, verbose=False) # Set verbose=False
            print(f"PCAP loaded: {len(capture.packets)} packets found.")

            for pkt_idx, pkt in enumerate(capture.packets):
                if verbose and (pkt_idx + 1) % 500 == 0:
                    print(f"  Processed {pkt_idx + 1} packets...")

                try:
                    ethFrame = ethernet.Ethernet(pkt.raw())
                    src_mac = ethFrame.src.decode('latin-1') # Adjust decoding if needed
                    dst_mac = ethFrame.dst.decode('latin-1')

                    protocol = None
                    src_ip, dst_ip = "", ""
                    src_port, dst_port = "", ""
                    anomaly_found = False # Reset per packet

                    # --- Anomaly Check Logic (mirrors live capture) ---
                    src_oui = normalize_mac_to_oui(src_mac)
                    dst_oui = normalize_mac_to_oui(dst_mac)

                    # Check Source OUI
                    if src_oui and src_oui not in BASELINE_DATA['known_ouis']:
                        anomaly_found = True
                        if verbose: print(f"    [Anomaly] Unknown Src OUI: {src_mac} ({src_oui})")

                    # Check Destination OUI (ignore broadcast/multicast MACs for baseline check)
                    if dst_oui:
                        is_broadcast = dst_mac == "ff:ff:ff:ff:ff:ff"
                        is_multicast = False
                        try:
                            if not is_broadcast and (int(dst_oui[:2], 16) & 1) == 1: is_multicast = True
                        except ValueError: pass

                        if not is_broadcast and not is_multicast and dst_oui not in BASELINE_DATA['known_ouis']:
                            anomaly_found = True
                            if verbose: print(f"    [Anomaly] Unknown Dst OUI: {dst_mac} ({dst_oui})")


                    # --- Protocol Identification & Check ---
                    if ethFrame.type == 2048:  # IPv4
                        ipPacket = ip.IP(unhexlify(ethFrame.payload))
                        src_ip = ipPacket.src.decode('latin-1')
                        dst_ip = ipPacket.dst.decode('latin-1')

                        if ipPacket.p == 6:  # TCP
                            protocol = "TCP"
                            tcpPacket = tcp.TCP(unhexlify(ipPacket.payload))
                            src_port = str(tcpPacket.src_port)
                            dst_port = str(tcpPacket.dst_port)
                        elif ipPacket.p == 17:  # UDP
                            protocol = "UDP"
                            udpPacket = udp.UDP(unhexlify(ipPacket.payload))
                            src_port = str(udpPacket.src_port)
                            dst_port = str(udpPacket.dst_port)
                        elif ipPacket.p == 1:  # ICMP
                            protocol = "ICMP"
                        # Add other IP protocols if needed (e.g., IGMP = 2)

                    elif ethFrame.type == 2054:  # ARP
                        protocol = "ARP"
                        # Basic ARP payload parsing (pcapfile might need manual parsing for details)
                        # Let's keep IPs as 0.0.0.0 for simplicity with pcapfile
                        src_ip = "0.0.0.0" # Placeholder
                        dst_ip = "0.0.0.0" # Placeholder
                        # Note: A more robust ARP parse might be needed if IPs are critical here.

                    # --- Final Anomaly Check (Protocol) & Recording ---
                    if protocol:
                        if protocol not in BASELINE_DATA['allowed_protocols']:
                            anomaly_found = True
                            if verbose: print(f"    [Anomaly] Disallowed Protocol: {protocol}")

                        # If *any* anomaly was found for this packet, record it
                        if anomaly_found:
                            anomalies_found_in_file += 1
                            # Format ports only if TCP/UDP
                            src_port_formatted = format_port(src_port, protocol) if protocol in ["TCP", "UDP"] else ""
                            dst_port_formatted = format_port(dst_port, protocol) if protocol in ["TCP", "UDP"] else ""

                            # Use raw ports in the key for uniqueness, formatted ports for CSV
                            conn_key = f"{protocol}|{src_mac}|{src_ip}|{src_port}|{dst_mac}|{dst_ip}|{dst_port}"
                            CONNECTION_STATS[conn_key] += 1


                except Exception as e:
                    # Catch errors parsing a single packet within the pcap
                    if verbose:
                        print(f"  Error processing packet #{pkt_idx+1}: {e}", file=sys.stderr)
                    continue # Skip to next packet

            print(f"Finished processing PCAP. Found {anomalies_found_in_file} potential anomalies.")

            # --- Output ---
            if not output_file:
                pcap_basename = os.path.splitext(os.path.basename(pcap_file))[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(OUTPUT_DIR, f"{pcap_basename}_anomalies_{timestamp}.csv")

            write_anomalies_to_csv(output_file, macOBJ) # Pass macOBJ for consistent lookup
            print(f"Analysis complete. Results written to {output_file}")
            return output_file

    except FileNotFoundError:
        print(f"Error: PCAP file not found at {pcap_file}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error processing PCAP file {pcap_file}: {e}", file=sys.stderr)
        return None

# --- CSV Writing Function ---
def write_anomalies_to_csv(output_file, mac_lookup_obj=None):
    """Write the collected anomalies (from CONNECTION_STATS) to a CSV file."""
    global CONNECTION_STATS

    if not CONNECTION_STATS:
        print("No anomalies recorded, CSV file not created.")
        return None # Return None if no file created

    print(f"Writing {len(CONNECTION_STATS)} unique anomalous connection types to {output_file}...")

    try:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['PROTOCOL', 'SRCMAC', 'SRCMFG', 'SRCIP', 'SRCPORT',
                          'DSTMAC', 'DSTMFG', 'DSTIP', 'DSTPORT', 'CNT']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # No grouping needed anymore, CONNECTION_STATS holds unique anomalous flows
            for conn_key, count in CONNECTION_STATS.items():
                parts = conn_key.split('|')
                protocol, src_mac, src_ip, src_port_raw, dst_mac, dst_ip, dst_port_raw = parts

                # Get manufacturer info using the consistent method
                src_mfg = get_manufacturer(src_mac, mac_lookup_obj)
                dst_mfg = get_manufacturer(dst_mac, mac_lookup_obj)

                # Format ports for CSV output
                src_port_formatted = format_port(src_port_raw, protocol)
                dst_port_formatted = format_port(dst_port_raw, protocol)

                # Write row
                writer.writerow({
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
                })

        print(f"CSV file written successfully: {output_file}")
        return output_file

    except Exception as e:
        print(f"Error writing CSV file {output_file}: {e}", file=sys.stderr)
        return None

# --- Live Capture Packet Processor ---
def process_packet_combined_check(packet):
    """Process a single packet captured by Scapy, log anomalies."""
    global BASELINE_DATA, CONNECTION_STATS, RUNNING # Declare globals used

    if not RUNNING: return # Exit if shutdown initiated

    try: # Add top-level error handling for the callback
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

            protocol = None
            src_ip, dst_ip = "", ""
            src_port, dst_port = "", ""
            anomaly_found = False # Reset per packet

            # --- Anomaly Check Logic ---
            src_oui = normalize_mac_to_oui(src_mac)
            dst_oui = normalize_mac_to_oui(dst_mac)

            # Check Source OUI
            if src_oui and src_oui not in BASELINE_DATA['known_ouis']:
                anomaly_found = True

            # Check Destination OUI (ignore broadcast/multicast MACs for baseline check)
            if dst_oui:
                is_broadcast = dst_mac == "ff:ff:ff:ff:ff:ff"
                is_multicast = False
                try: # Check multicast bit (first octet, least significant bit)
                    if not is_broadcast and (int(dst_oui[:2], 16) & 1) == 1: is_multicast = True
                except ValueError: pass # Ignore if OUI is malformed

                if not is_broadcast and not is_multicast and dst_oui not in BASELINE_DATA['known_ouis']:
                    anomaly_found = True

            # --- Protocol Identification & Check ---
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if TCP in packet:
                    protocol = "TCP"
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                elif ICMP in packet:
                    protocol = "ICMP"
                # Add other IP protocols if needed (e.g., packet.haslayer(IGMP))

            elif ARP in packet:
                protocol = "ARP"
                # Scapy provides parsed ARP fields
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst

            # --- Final Anomaly Check (Protocol) & Recording ---
            if protocol:
                if protocol not in BASELINE_DATA['allowed_protocols']:
                    anomaly_found = True

                # If *any* anomaly was found for this packet, record it
                if anomaly_found:
                    # Use raw ports in the key for uniqueness
                    conn_key = f"{protocol}|{src_mac}|{src_ip}|{src_port}|{dst_mac}|{dst_ip}|{dst_port}"
                    CONNECTION_STATS[conn_key] += 1

    except Exception as e:
        # Log error processing a single packet during live capture
        print(f"Error processing live packet: {e} - Packet summary: {packet.summary()}", file=sys.stderr)
        # Continue capturing other packets

# --- Signal Handler ---
def signal_handler(sig, frame):
    """Handle Ctrl+C and other termination signals gracefully."""
    global RUNNING
    if RUNNING: # Prevent multiple prints if signal received multiple times
        print("\n[!] Termination signal received. Stopping capture and exporting final data...", file=sys.stderr)
        RUNNING = False # Signal the main loop and sniff to stop

# --- Main Execution ---
def main():
    # Declare globals modified/read in main
    global EXPORT_INTERVAL, OUTPUT_DIR, RUNNING, LAST_EXPORT_TIME, BASELINE_DATA, CONNECTION_STATS

    parser = argparse.ArgumentParser(
        description="Network Anomaly Detector. Captures or reads network traffic, compares against OUI and Protocol baselines, and logs anomalous connections to CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )

    # --- Argument Parsing ---
    # Baseline paths
    default_oui_baseline = os.path.join(BASELINE_DIR, "oui_baseline.pkl")
    default_protocol_baseline = os.path.join(BASELINE_DIR, "protocol_baseline.pkl")
    parser.add_argument("-ob", "--oui-baseline", default=default_oui_baseline,
                        help="Path to the OUI baseline pickle file.")
    parser.add_argument("-pb", "--protocol-baseline", default=default_protocol_baseline,
                        help="Path to the Protocol baseline pickle file.")

    # Input source (Live interface OR PCAP file)
    input_group = parser.add_mutually_exclusive_group(required=True)
    if SCAPY_AVAILABLE:
        input_group.add_argument("-i", "--iface",
                                 help="Network interface name for live capture (e.g., eth0, en0). Requires Scapy.")
    input_group.add_argument("-r", "--read-pcap",
                             help="Path to a PCAP file to read and analyze.")

    # Output options
    parser.add_argument("-o", "--output-dir", default=OUTPUT_DIR,
                        help="Directory to save the CSV output files.")
    parser.add_argument("-f", "--output-file",
                        help="Specific base output file name for CSV (timestamp may be added). If omitted, generated automatically.")
    parser.add_argument("-t", "--interval", type=int, default=int(EXPORT_INTERVAL/60),
                        help="Interval in minutes between CSV exports during live capture.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output during processing.")

    args = parser.parse_args()

    # --- Initialization ---
    OUTPUT_DIR = args.output_dir
    EXPORT_INTERVAL = args.interval * 60
    if EXPORT_INTERVAL <= 0:
        print("Warning: Export interval must be positive. Using default (10 minutes).", file=sys.stderr)
        EXPORT_INTERVAL = 600

    # Create output directory
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True) # exist_ok=True avoids error if dir exists
        print(f"Output directory: {os.path.abspath(OUTPUT_DIR)}")
    except Exception as e:
        print(f"Error creating output directory '{OUTPUT_DIR}': {e}", file=sys.stderr)
        sys.exit(1)

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"""
╔════════════════════════════════════════════════╗
║     NETWORK ANOMALY DETECTOR WITH PCAP         ║
╚════════════════════════════════════════════════╝
""")

    # --- Load Baselines ---
    oui_loaded = False
    try:
        if os.path.exists(args.oui_baseline):
            with open(args.oui_baseline, 'rb') as f:
                data = pickle.load(f)
                # Adapt based on expected format
                if isinstance(data, dict) and 'known_ouis' in data:
                    BASELINE_DATA['known_ouis'] = data['known_ouis']
                elif isinstance(data, dict): # Assume direct OUI:MFG dict
                    BASELINE_DATA['known_ouis'] = data
                else:
                     print(f"Warning: Unknown format in OUI baseline file: {args.oui_baseline}", file=sys.stderr)

                if BASELINE_DATA['known_ouis']:
                    print(f"Loaded {len(BASELINE_DATA['known_ouis'])} OUI entries from {args.oui_baseline}")
                    oui_loaded = True
        if not oui_loaded:
            print(f"Warning: OUI baseline file not found or empty at {args.oui_baseline}. OUI checks disabled.", file=sys.stderr)
    except Exception as e:
        print(f"Error loading OUI baseline '{args.oui_baseline}': {e}", file=sys.stderr)
        # Decide if you want to exit or continue without OUI checks
        # sys.exit(1)

    proto_loaded = False
    try:
        if os.path.exists(args.protocol_baseline):
            with open(args.protocol_baseline, 'rb') as f:
                data = pickle.load(f)
                 # Adapt based on expected format
                if isinstance(data, dict) and 'allowed_protocols' in data:
                    BASELINE_DATA['allowed_protocols'] = data['allowed_protocols']
                elif isinstance(data, set): # Assume direct set of protocols
                    BASELINE_DATA['allowed_protocols'] = data
                else:
                    print(f"Warning: Unknown format in Protocol baseline file: {args.protocol_baseline}", file=sys.stderr)

                if BASELINE_DATA['allowed_protocols']:
                     print(f"Loaded {len(BASELINE_DATA['allowed_protocols'])} allowed protocol entries from {args.protocol_baseline}")
                     proto_loaded = True
        if not proto_loaded:
             print(f"Warning: Protocol baseline file not found or empty at {args.protocol_baseline}. Protocol checks disabled.", file=sys.stderr)
    except Exception as e:
        print(f"Error loading protocol baseline '{args.protocol_baseline}': {e}", file=sys.stderr)
        # Decide if you want to exit or continue without protocol checks
        # sys.exit(1)

    # --- Determine Output File Base ---
    # For PCAP mode, it's handled within process_pcap_file
    # For Live mode, we use it for interval exports
    output_file_base = None
    if args.output_file:
        # Ensure it's just a filename, not a full path initially
        output_file_base = os.path.basename(args.output_file)
        # Remove extension if present, we'll add .csv
        output_file_base = os.path.splitext(output_file_base)[0]


    # --- Mode Selection ---
    macOBJ = MAC() # Create MAC object once for live capture if needed

    if args.read_pcap:
        # PCAP File Processing Mode
        process_pcap_file(args.read_pcap, args.output_file, args.verbose) # Pass output file directly if specified

    elif args.iface and SCAPY_AVAILABLE:
        # Live Capture Mode
        print(f"Starting live capture on interface {args.iface}...")
        print(f"Anomalous connections CSVs will be saved to: {OUTPUT_DIR}")
        print(f"Export interval: {args.interval} minutes")

        LAST_EXPORT_TIME = time.time() # Initialize export timer

        try:
            # Platform specific filter (optional, Scapy usually handles this well)
            # Consider removing if causing issues, Scapy's default might be fine
            system = platform.system().lower()
            packet_filter = "" # Start with no filter
            # Example: packet_filter = "tcp or udp or icmp or arp"
            # Be careful with filters, they might exclude needed context.
            # If performance is an issue, consider filtering later or using BPF syntax.

            if packet_filter:
                print(f"Using packet filter: '{packet_filter}'")
            else:
                print("No specific packet filter applied (capturing relevant layers).")

            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting packet capture loop...")
            print("Press Ctrl+C to stop.")

            while RUNNING:
                try:
                    # Sniff packets - use store=0, consider lower count/timeout for responsiveness
                    sniff(iface=args.iface,
                          filter=packet_filter,
                          prn=process_packet_combined_check,
                          store=0, # Don't store packets in memory
                          # count=1000, # Process in chunks
                          timeout=EXPORT_INTERVAL, # Wake up periodically anyway
                          stop_filter=lambda x: not RUNNING) # Check RUNNING flag more often

                    # Check if it's time to export (or if sniff timed out)
                    current_time = time.time()
                    # Add a small buffer (e.g., 1 second) to avoid exporting slightly too early
                    if (current_time - LAST_EXPORT_TIME >= EXPORT_INTERVAL - 1) and RUNNING:
                        if CONNECTION_STATS: # Only write if there's data
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            if output_file_base:
                                current_output_file = os.path.join(OUTPUT_DIR, f"{output_file_base}_{timestamp}.csv")
                            else:
                                current_output_file = os.path.join(OUTPUT_DIR, f"live_anomalies_{timestamp}.csv")

                            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Exporting {len(CONNECTION_STATS)} anomalies to {current_output_file}...")
                            write_anomalies_to_csv(current_output_file, macOBJ) # Pass macOBJ
                            # Reset stats after successful export
                            CONNECTION_STATS = defaultdict(int)
                        else:
                             print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No new anomalies detected during this interval.")

                        LAST_EXPORT_TIME = current_time # Reset timer

                except OSError as e:
                    # Handle potential interface errors (e.g., interface down)
                     print(f"\n[!] Interface error on {args.iface}: {e}", file=sys.stderr)
                     print("    Check if the interface is up and privileges are sufficient.")
                     print("    Stopping capture.")
                     RUNNING = False # Stop the main loop
                except Exception as e:
                    # Catch other unexpected errors during the sniff/export cycle
                    print(f"\n[!] Error during live capture loop: {e}", file=sys.stderr)
                    print("    Attempting to continue...")
                    time.sleep(5) # Pause before retrying

            # --- Final Export on Shutdown ---
            print("\nCapture loop stopped.")
            if CONNECTION_STATS:
                print("Performing final export of remaining anomalies...")
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if output_file_base:
                     final_output_file = os.path.join(OUTPUT_DIR, f"{output_file_base}_final_{timestamp}.csv")
                else:
                     final_output_file = os.path.join(OUTPUT_DIR, f"live_anomalies_final_{timestamp}.csv")
                write_anomalies_to_csv(final_output_file, macOBJ)
                print(f"Final export completed to {final_output_file}")
            else:
                print("No remaining anomalies to export.")

        except PermissionError:
             print(f"\n[!] Permission Error: Failed to capture on {args.iface}.", file=sys.stderr)
             print( "   Please run the script with sufficient privileges (e.g., using 'sudo').")
             sys.exit(1)
        except OSError as e:
             # Catch specific OSError for interface not found before loop starts
             print(f"\n[!] Network Interface Error: {e}", file=sys.stderr)
             print(f"    Could not start capture on interface '{args.iface}'. Check if the name is correct and the interface exists/is up.")
             sys.exit(1)
        except KeyboardInterrupt:
             # This is now handled by the signal handler setting RUNNING=False
             print("\nShutdown requested via KeyboardInterrupt.")
        except Exception as e:
             # Catch any other unexpected errors during setup/main loop start
             print(f"\n[!] An unexpected error occurred: {e}", file=sys.stderr)
        finally:
             print("\nDetector shutdown complete.")

    elif not SCAPY_AVAILABLE:
        print("Error: Scapy is required for live capture (-i option). Please install it (`pip install scapy`) or use the -r option to read a PCAP file.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Check for root/admin privileges if live capture is likely needed
    # This is a basic check and might need adjustment for specific OS/setups
    if '-i' in sys.argv or '--iface' in sys.argv:
         try:
             # Simple check: try getting UID (Linux/macOS) or check admin status (Windows)
             is_admin = (os.geteuid() == 0) if hasattr(os, 'geteuid') else (ctypes.windll.shell32.IsUserAnAdmin() != 0)
             if not is_admin:
                 print("Warning: Live capture usually requires root/administrator privileges.", file=sys.stderr)
                 # Optionally exit here, or let Scapy fail later
                 # sys.exit("Please run with sudo or as administrator for live capture.")
         except Exception: # Handle cases where checks aren't available or fail
             print("Warning: Could not determine privilege level. Live capture might require root/administrator rights.", file=sys.stderr)
             # Import ctypes only if needed for Windows check
             import ctypes


    main()
