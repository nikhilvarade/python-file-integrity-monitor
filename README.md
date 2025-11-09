# Python File Integrity Monitor (FIM)

A command-line security tool built in Python to detect unauthorized changes to files within a specified directory.

This script creates a secure baseline of a directory by storing the SHA-256 hashes of all files in an **SQLite database**. On subsequent runs, it re-scans the directory, compares the new hashes to the baseline, and reports any files that have been **MODIFIED**, **ADDED**, or **DELETED**.

## Features
* **SQLite Backend:** Uses a scalable SQLite database to store file baselines, making it efficient for many files.
* **Flexible Scanning:** Can monitor an entire directory (and its subdirectories) or a single file.
* **Change Detection:** Clearly reports on `MODIFIED`, `ADDED`, and `DELETED` files.
* **Secure Hashing:** Uses the SHA-256 algorithm to "fingerprint" files.
* **Command-Line Interface:** Uses `argparse` to function as a proper, reusable command-line tool.

## Technologies Used
* **Python**
* **sqlite3:** For database storage.
* **hashlib:** For SHA-256 hashing.
* **argparse:** For the command-line interface.
* **os:** For walking directory paths.

## How to Use

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/nikhilvarade/python-file-integrity-monitor.git](https://github.com/nikhilvarade/python-file-integrity-monitor.git)
    cd python-file-integrity-monitor
    ```

2.  **Create the Baseline:**
    Run the script for the first time, pointing it at the directory or file you want to monitor. It will scan the path and create a `fim.db` database file.

    ```bash
    # To scan a whole folder
    python3 fim.py /path/to/your/folder
    
    # To scan a single file
    python3 fim.py /path/to/your/file.txt
    ```
    *Output:*
    ```
    Creating new baseline...
    Scanning: /path/to/your/folder

    --- Baseline created successfully at fim.db ---
    Total files scanned: 50
    ```

3.  **Check for Changes:**
    Run the *exact same command* again at any time. The script will see that `fim.db` exists and will use it to check for changes.

    * **If no changes are found:**
        ```bash
        Checking file integrity for: /path/to/your/folder
        
        ---No changes detected. All files are intact.---
        ```
    * **If changes are found:**
        ```bash
        Checking file integrity for: /path/to/your/folder
        
        MODIFIED: /path/to/your/folder/important_file.txt
        ADDED: /path/to/your/folder/new_file.log
        DELETED: /path/to/your/folder/old_file.txt

        ---Integrity check complete. changes were found.---
        ```

4.  **To Reset the Baseline:**
    Simply delete the `fim.db` file. The next time you run the script, it will create a new, fresh baseline.
    ```bash
    rm fim.db
    ```
