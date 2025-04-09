# create_oui_baseline.py
import pickle
import argparse
import re
import os

# --- Define Known Devices/Manufacturers Here ---
# Format: "OUI": "Manufacturer Name"
# OUI should be the first 6 hex digits of the MAC address.
# Use uppercase and no colons/hyphens for consistency during lookup.
# You can find OUIs using online lookup tools (e.g., search "MAC OUI lookup")
KNOWN_OUI_MFG_DATA = {
    "B827EB": "Raspberry Pi Foundation",      # B8:27:EB
    "DCA632": "Raspberry Pi Trading Ltd",     # DC:A6:32
    "005056": "VMware, Inc.",                 # 00:50:56
    "000C29": "VMware, Inc.",                 # 00:0C:29
    "001C42": "Cisco Systems, Inc",           # 00:1C:42 (Example)
    "000142": "Cisco Systems, Inc",           # 00:01:42 (Example)
    "00155D": "Microsoft Corporation",        # 00:15:5D (Hyper-V NIC)
    "F875A4": "Dell Inc.",                    # F8:75:A4 (Example)
    "A0D3C1": "Apple, Inc.",                  # A0:D3:C1 (Example)
    "001AA0": "Google, Inc.",                 # 00:1A:A0 (Example)
    "001517": "Intel Corporate",              # 00:15:17 (Example)
    "003018": "Jetway Information Co., Ltd.", # 00:30:18 (Example)
    # --- Add more known manufacturers/OUIs based on your inventory ---
    # Example adding an Allen-Bradley / Rockwell OUI
    # "0000C5": "Rockwell Automation/Allen-Bradley",
    # Example adding a Siemens OUI
    # "001C06": "Siemens AG, Industry Sector",
}
# --- End Known Device Definitions ---

def normalize_oui(oui_string):
    """Converts OUI string to uppercase and removes separators."""
    if not isinstance(oui_string, str):
        return None
    # Remove colons, hyphens, periods
    # Fix: Escape the hyphen by placing it at the end or beginning of the character class
    cleaned = re.sub(r'[:.\-]', '', oui_string)
    # Ensure it's exactly 6 hex characters
    if len(cleaned) == 6 and all(c in '0123456789ABCDEFabcdef' for c in cleaned):
        return cleaned.upper()
    else:
        print(f"Warning: Skipping invalid OUI format during normalization: '{oui_string}'")
        return None

def create_manual_baseline(output_pickle_file):
    """Creates a baseline pickle file from manually defined known OUIs."""
    known_ouis = {}
    print("Processing manually defined known devices...")

    # Create the directory if it doesn't exist
    output_dir = os.path.dirname(output_pickle_file)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"Created directory: {output_dir}")
        except Exception as e:
            print(f"Error creating directory {output_dir}: {e}")
            return

    invalid_count = 0
    for oui_key, mfg_name in KNOWN_OUI_MFG_DATA.items():
        normalized = normalize_oui(oui_key)
        if normalized:
            if normalized in known_ouis:
                 print(f"Warning: Duplicate normalized OUI '{normalized}' found for '{mfg_name}' and '{known_ouis[normalized]}'. Overwriting.")
            known_ouis[normalized] = mfg_name
            # print(f"  Adding OUI: {normalized} ({mfg_name})") # Uncomment for verbose output
        else:
            invalid_count += 1
            print(f"Warning: Invalid OUI key format in definition: '{oui_key}' for '{mfg_name}'. Skipping.")


    if invalid_count > 0:
        print(f"\nWarning: Skipped {invalid_count} invalid OUI definitions.")

    if not known_ouis:
        print("Error: No valid known OUIs were processed. Baseline file will be empty or contain only other potential data.")
        # Decide whether to proceed or exit
        # sys.exit(1) # Optional: exit if no OUIs are defined

    # The final structure to be pickled
    # We store it under the key 'known_ouis' for clarity in the detector script
    baseline_data = {
        'known_ouis': known_ouis
        # You could potentially add other manually defined baseline components here,
        # like allowed protocols, specific IPs, etc., if needed later.
    }

    try:
        with open(output_pickle_file, 'wb') as f:
            pickle.dump(baseline_data, f)
        print(f"\nManual OUI baseline with {len(known_ouis)} entries saved successfully to '{output_pickle_file}'")
    except Exception as e:
        print(f"\nError saving baseline file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a network baseline pickle file from manually defined Manufacturer OUIs.")
    parser.add_argument("-o", "--output", default="pickle_files/oui_baseline.pkl",
                        help="Path to save the output baseline pickle file (default: pickle_files/oui_baseline.pkl).")
    args = parser.parse_args()

    create_manual_baseline(args.output)

# --- How to run ---
# 1. Edit the KNOWN_OUI_MFG_DATA dictionary in this script with your known devices.
# 2. Run the script:
#    python create_oui_baseline.py -o pickle_files/my_device_baseline.pkl
