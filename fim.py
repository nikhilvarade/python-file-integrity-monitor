# --- Version 3 Code (Final) ---
import os
import hashlib
import sqlite3
import argparse
import sys

# --- Configuration ---
BASELINE_DB = "fim.db" # We now use a database file
# ---------------------

def get_file_hash(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read the file in chunks for efficiency
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def scan_path(target_path):
    """
    Scans a target path (file or directory) and returns
    a dictionary of {file_path: hash}.
    """
    scan_data = {}
    if os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                file_hash = get_file_hash(file_path)
                if file_hash:
                    scan_data[file_path] = file_hash
    elif os.path.isfile(target_path):
        file_hash = get_file_hash(target_path)
        if file_hash:
            scan_data[target_path] = file_hash
    return scan_data

def create_baseline(target_path):
    """Scans the target path and creates a new SQLite baseline."""
    print(f"Creating new baseline...\nScanning: {target_path}\n")
    
    baseline_data = scan_path(target_path)
    if not baseline_data:
        print("No files found to baseline. Exiting.")
        return

    # --- NEW SQL LOGIC ---
    try:
        # Connect to the database
        conn = sqlite3.connect(BASELINE_DB)
        cursor = conn.cursor()
        
        # Create a table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            filepath TEXT PRIMARY KEY,
            hash TEXT NOT NULL
        )
        """)
        
        # Loop and insert all data
        for path, hash_val in baseline_data.items():
            cursor.execute("REPLACE INTO baseline (filepath, hash) VALUES (?, ?)", (path, hash_val))
        
        # Commit the changes
        conn.commit()
        
        # Close the connection
        conn.close()
        
        print(f"--- Baseline created successfully at {BASELINE_DB} ---")
        print(f"Total files scanned: {len(baseline_data)}")

    except Exception as e:
        print(f"Error creating/writing to database: {e}")

def check_integrity(target_path):
    """Checks the target path against the existing SQLite baseline."""
    print(f"Checking file integrity for: {target_path}\n")
    
    # 1. Load the old baseline from the database
    old_baseline = {}
    try:
        conn = sqlite3.connect(BASELINE_DB)
        cursor = conn.cursor()
        
        # Check if the table exists first
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='baseline'")
        if not cursor.fetchone():
            print(f"Error: Baseline table 'baseline' not found in {BASELINE_DB}.")
            print("Please run without the baseline file to create a new one.")
            conn.close()
            return

        # Select all data from the table
        for row in cursor.execute("SELECT filepath, hash FROM baseline"):
            old_baseline[row[0]] = row[1]
        conn.close()
        
    except Exception as e:
        print(f"Error: Could not load baseline from database '{BASELINE_DB}'. {e}")
        return

    # 2. Perform a new scan
    new_scan = scan_path(target_path)

    # 3. Compare the two sets of files
    old_files = set(old_baseline.keys())
    new_files = set(new_scan.keys())

    added_files = new_files - old_files
    deleted_files = old_files - new_files
    common_files = old_files.intersection(new_files)

    # 4. Report changes
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
        print("---No changes detected. All files are intact.---")
    else:
        print("\n---Integrity check complete. changes were found.---")


# --- Main execution block ---
if __name__ == "__main__":
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    
    # Add one "positional" argument: the path to monitor
    parser.add_argument("target", help="The file or directory to monitor")
    
    # Parse the arguments provided by the user
    args = parser.parse_args()

    # Get the path and convert it to an absolute path
    target_path = os.path.abspath(args.target)

    # Check if the path exists before doing anything
    if not os.path.exists(target_path):
        print(f"Error: Path does not exist: {target_path}")
        sys.exit(1) # Exit the script with an error code

    # This logic is the same, but now passes the path
    if not os.path.exists(BASELINE_DB):
        create_baseline(target_path)
    else:
        check_integrity(target_path)
