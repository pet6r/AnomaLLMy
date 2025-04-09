# create_protocol_baseline.py
import pickle
import argparse
import sys
import os

# --- Define Allowed Protocols Here ---
# Add the names of protocols you expect and want to allow.
# Use uppercase names. Scapy's sprintf often returns lowercase,
# so we'll normalize to uppercase during the check.
# Common examples:
ALLOWED_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP", # Covers ICMP for IPv4
    "IPV6-ICMP", # Covers ICMP for IPv6
    "ARP",
    # "IGMP", # Example: If you expect multicast group management
    # "LLDP", # Example: Link Layer Discovery Protocol
    # Add any other specific L2/L3 protocols expected in your environment
    # E.g., specific industrial protocols if they have unique EtherTypes/IP proto numbers Scapy recognizes
}
# --- End Allowed Protocol Definitions ---

def create_protocol_baseline(output_pickle_file):
    """Creates a baseline pickle file containing a set of allowed protocol names."""
    print("Processing defined allowed protocols...")
    if not isinstance(ALLOWED_PROTOCOLS, set):
        print("Error: ALLOWED_PROTOCOLS should be a set.", file=sys.stderr)
        return

    # Create the directory if it doesn't exist
    output_dir = os.path.dirname(output_pickle_file)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"Created directory: {output_dir}")
        except Exception as e:
            print(f"Error creating directory {output_dir}: {e}")
            return

    # Ensure all names are uppercase for consistent comparison later
    normalized_protocols = {proto.upper() for proto in ALLOWED_PROTOCOLS}

    if not normalized_protocols:
        print("Warning: No protocols defined in ALLOWED_PROTOCOLS. Baseline will be empty.")

    # Structure to be pickled
    baseline_data = {
        'allowed_protocols': normalized_protocols
    }

    try:
        with open(output_pickle_file, 'wb') as f:
            pickle.dump(baseline_data, f)
        print(f"\nProtocol baseline with {len(normalized_protocols)} entries saved successfully to '{output_pickle_file}'")
        print(f"Allowed protocols: {', '.join(sorted(list(normalized_protocols)))}")
    except Exception as e:
        print(f"\nError saving baseline file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a network baseline pickle file defining allowed protocols.")
    parser.add_argument("-o", "--output", default="pickle_files/protocol_baseline.pkl",
                        help="Path to save the output protocol baseline pickle file (default: pickle_files/protocol_baseline.pkl).")
    args = parser.parse_args()

    create_protocol_baseline(args.output)

# --- How to run ---
# 1. Edit the ALLOWED_PROTOCOLS set in this script.
# 2. Run the script:
#    python create_protocol_baseline.py -o pickle_files/my_protocol_rules.pkl
