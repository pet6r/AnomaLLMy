#!/usr/bin/env python3
# create_comprehensive_oui.py - Parses a Wireshark-style 'manuf' file
# to create a comprehensive OUI->MFG pickle lookup file.

import pickle
import argparse
import re
import os
import sys

def normalize_oui(oui_string):
    """
    Converts an OUI string (potentially with separators)
    to an uppercase, 6-character hex string without separators.
    Returns None if the input cannot be normalized to a valid 6-char OUI.
    """
    if not isinstance(oui_string, str):
        return None
    # Remove colons, hyphens, periods
    # Hyphen needs escaping or placement at start/end of []
    cleaned = re.sub(r'[:.-]', '', oui_string)
    # We only care about the first 6 characters for the standard OUI
    oui_part = cleaned[:6]
    # Validate: must be exactly 6 hex characters
    if len(oui_part) == 6 and all(c in '0123456789ABCDEFabcdef' for c in oui_part):
        return oui_part.upper()
    else:
        return None # Invalid format or length

def create_comprehensive_pickle(input_manuf_file, output_pickle_file, verbose=False):
    """
    Reads the input manuf file, parses OUI/MFG pairs, and saves
    them as a dictionary {OUI: MFG_NAME} to the output pickle file.
    """
    print(f"Processing manufacturer file: {input_manuf_file}")
    oui_map = {}
    lines_processed = 0
    entries_added = 0
    entries_skipped = 0
    duplicates_found = 0

    try:
        # Try UTF-8 first, common for newer files
        encodings_to_try = ['utf-8', 'latin-1']
        file_handle = None
        for enc in encodings_to_try:
             try:
                  file_handle = open(input_manuf_file, 'r', encoding=enc)
                  print(f"Opened file with encoding: {enc}")
                  break # Success
             except UnicodeDecodeError:
                  print(f"Failed to decode with {enc}, trying next...")
                  continue
        if file_handle is None:
             print(f"Error: Could not decode file {input_manuf_file} with tested encodings.", file=sys.stderr)
             return

        with file_handle:
            for line in file_handle:
                lines_processed += 1
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Split by tab. Expecting at least 3 fields based on header.
                parts = line.split('\t', 2) # Split into max 3 parts

                if len(parts) < 3:
                    if verbose:
                        print(f"  Skipping line {lines_processed}: Not enough columns - '{line}'")
                    entries_skipped += 1
                    continue

                oui_str = parts[0].strip()
                # Use the full vendor name from the 3rd column
                mfg_name = parts[2].strip()

                if not mfg_name:
                    if verbose:
                         print(f"  Skipping line {lines_processed}: Missing manufacturer name - '{line}'")
                    entries_skipped += 1
                    continue

                normalized = normalize_oui(oui_str)

                if normalized:
                    # OUI is valid, add/update the map
                    if normalized in oui_map:
                        if verbose and oui_map[normalized] != mfg_name:
                             print(f"  Warning line {lines_processed}: Duplicate OUI '{normalized}'. Overwriting '{oui_map[normalized]}' with '{mfg_name}'")
                        duplicates_found +=1
                        # Decide whether to overwrite or keep first (overwriting is simpler)
                    oui_map[normalized] = mfg_name
                    entries_added += 1
                else:
                    # OUI string couldn't be normalized (e.g., too short, invalid chars)
                    if verbose:
                        print(f"  Skipping line {lines_processed}: Could not normalize OUI '{oui_str}' from line '{line}'")
                    entries_skipped += 1

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_manuf_file}'", file=sys.stderr)
        return
    except Exception as e:
        print(f"An error occurred while processing the file: {e}", file=sys.stderr)
        return

    print("-" * 30)
    print(f"Processing Summary:")
    print(f"  Lines Processed: {lines_processed}")
    print(f"  Entries Added/Updated: {entries_added}")
    print(f"  Entries Skipped: {entries_skipped}")
    print(f"  Duplicate OUIs Found (updated): {duplicates_found}")
    print(f"  Final Dictionary Size: {len(oui_map)}")
    print("-" * 30)

    if not oui_map:
        print("Warning: No valid OUI entries found. Output file will be empty.", file=sys.stderr)
        # Optionally return here if an empty file is not desired
        # return

    # --- Save the dictionary to a pickle file ---
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_pickle_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            print(f"Created output directory: {output_dir}")

        with open(output_pickle_file, 'wb') as f:
            # Save the dictionary directly, not nested under 'known_ouis'
            pickle.dump(oui_map, f)
        print(f"\nComprehensive OUI dictionary saved successfully to '{output_pickle_file}'")

    except Exception as e:
        print(f"\nError saving pickle file '{output_pickle_file}': {e}", file=sys.stderr)


if __name__ == "__main__":
    # Suggest default output location relative to baseline dir for consistency
    default_output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "baseline", "pickle_files")
    default_output_file = os.path.join(default_output_dir, "oui_comprehensive.pkl")

    parser = argparse.ArgumentParser(
        description="Parse a Wireshark 'manuf' file and create a comprehensive OUI->Manufacturer pickle dictionary.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Path to the input 'manuf' file.")
    parser.add_argument("-o", "--output", default=default_output_file,
                        help="Path to save the output comprehensive OUI pickle file.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output (show skipped lines, duplicates).")
    args = parser.parse_args()

    create_comprehensive_pickle(args.input, args.output, args.verbose)

# --- How to run ---
# 1. Save this code as a Python file (e.g., create_comprehensive_oui.py).
#
# 2. Download the 'manuf' file (e.g., from Wireshark's site).
#
# 3. Run the script, providing the path to your 'manuf' file:
#    python3 create_comprehensive_oui.py -i /path/to/your/downloaded/manuf -o ../baseline/pickle_files/oui_comprehensive.pkl
#    (Adjust the output path -o if needed)
