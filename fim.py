# --- Version 1 Code ---
import os
import hashlib

# The directory you want to monitor
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

# --- Main part of the script ---
print(f"Scanning directory: {directory_to_watch}\n")
for root, dirs, files in os.walk(directory_to_watch):
    for filename in files:
        file_path = os.path.join(root, filename)
        file_hash = get_file_hash(file_path)
        
        if file_hash:
            print(f"File: {file_path} | Hash: {file_hash}")
