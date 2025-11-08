# --- Version 2 Code ---
import os
import hashlib
import json

BASELINE_FILE = "baseline.json"
# Make sure this path is correct on your system
directory_to_watch = "/home/nikhi_varade/my-test-folder" 

def get_file_hash(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def create_baseline():
    """Scans the directory and creates a new baseline.json file."""
    print(f"Creating new baseline...\nScanning directory: {directory_to_watch}\n")
    baseline_data = {}
    for root, dirs, files in os.walk(directory_to_watch):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_hash = get_file_hash(file_path)
            if file_hash:
                baseline_data[file_path] = file_hash
    try:
        with open(BASELINE_FILE, 'w') as f:
            json.dump(baseline_data, f, indent=4)
        print(f"--- Baseline created successfully at {BASELINE_FILE} ---")
    except Exception as e:
        print(f"Error saving baseline: {e}")

def check_integrity():
    """Checks the directory against the existing baseline."""
    print("Checking file integrity against baseline...\n")
    try:
        with open(BASELINE_FILE, 'r') as f:
            old_baseline = json.load(f)
    except Exception as e:
        print(f"Error: Could not load baseline file '{BASELINE_FILE}'. {e}")
        return

    new_scan = {}
    for root, dirs, files in os.walk(directory_to_watch):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_hash = get_file_hash(file_path)
            if file_hash:
                new_scan[file_path] = file_hash

    old_files = set(old_baseline.keys())
    new_files = set(new_scan.keys())
    added_files = new_files - old_files
    deleted_files = old_files - new_files
    common_files = old_files.intersection(new_files)

    changes_found = False
    for file_path in common_files:
        if old_baseline[file_path] != new_scan[file_path]:
            print(f"MODIFIED: {file_path}")
            changes_found = True
    for file_path in added_files:
        print(f"ADDED: {file_path}")
        changes_found = True
    for file_path in deleted_files:
        print(f"DELETED: {file_path}")
        changes_found = True

    if not changes_found:
        print("--- No changes detected. All files are intact. ---")
    else:
        print("\n--- Integrity check complete. Changes were found. ---")

# --- Main execution block ---
if __name__ == "__main__":
    if not os.path.exists(BASELINE_FILE):
        create_baseline()
    else:
        check_integrity()
