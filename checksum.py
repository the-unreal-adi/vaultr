import os
import sys
import hashlib
import sqlite3
import logging
from datetime import datetime, timezone, timedelta

# Ensure the logs directory exists before configuring logging
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs\\checksum-{datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d')}.log"),
        logging.StreamHandler()
    ]
)


def initialize_package():
    try:
        print("Initializing package...")
        with sqlite3.connect("checksum.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    checksum TEXT NOT NULL
                )
            """)
        conn.commit()
        print("Package initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing package: {e}")
        sys.exit(1)

def store_checksum(filepath):
    try:
        logging.info(f"Storing checksum for {filepath}")

        checksum_hash = hashlib.sha512()

        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                checksum_hash.update(chunk)

        checksum = checksum_hash.hexdigest()

        with sqlite3.connect("checksum.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO files (filename, checksum) VALUES (?, ?)",
                           (os.path.basename(filepath), checksum))
            conn.commit()
        logging.info(f"Stored checksum for {filepath}: {checksum}")

    except Exception as e:
        logging.error(f"Error storing checksum for {filepath}: {e}")

def create_checksum_file(source):
    try:
        initialize_package()
        if os.path.isdir(source):
            for root, _, files in os.walk(source):
                for file in files:
                    filepath = os.path.join(root, file)
                    store_checksum(filepath)
        else:
            logging.info(f"Creating checksum for file: {source}")
    except Exception as e:
        logging.error(f"Error creating checksum file: {e}")

def compare_checksums(source):
    try:
        logging.info(f"Comparing checksums for {source}")
        with sqlite3.connect("checksum.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT filename, checksum FROM files")
            stored_checksums = {row[0]: row[1] for row in cursor.fetchall()}

        if os.path.isdir(source):
            for root, _, files in os.walk(source):
                for file in files:
                    filepath = os.path.join(root, file)
                    checksum_hash = hashlib.sha512()
                    with open(filepath, "rb") as f:
                        while chunk := f.read(4096):
                            checksum_hash.update(chunk)
                    current_checksum = checksum_hash.hexdigest()

                    if file in stored_checksums:
                        if current_checksum == stored_checksums[file]:
                            logging.info(f"Checksum match for {file}")
                        else:
                            logging.warning(f"Checksum mismatch for {file}: "
                                            f"Stored: {stored_checksums[file]}, Current: {current_checksum}")
                    else:
                        logging.warning(f"No stored checksum for {file}. Current checksum: {current_checksum}")
        else:
            logging.warning(f"Source {source} is neither a file nor a directory.")
    except Exception as e:
        logging.error(f"Error comparing checksums: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("Create checksum: python checksum.py create <source>")
        print("Compare checksums: python checksum.py compare <source>")
        return

    action, source = sys.argv[1], sys.argv[2]

    if action == "create":
        create_checksum_file(source)
    elif action == "compare":
        compare_checksums(source)
    else:
        print("Invalid action. Use 'create' or 'compare'.")

if __name__ == "__main__":
    main()