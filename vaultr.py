import os
import sys
import hashlib
import sqlite3
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import logging
from datetime import datetime, timezone, timedelta

# Ensure the logs directory exists before configuring logging
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs\\vaultr-{datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d')}.log"),
        logging.StreamHandler()
    ]
)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())

def initialize_package():
    try:
        logging.info("Initializing package...")
        with sqlite3.connect("vaultr.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    filedata BLOB NOT NULL,
                    checksum TEXT NOT NULL
                )
            """)
        conn.commit()
        logging.info("Package initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error initializing package: {e}")
        sys.exit(1)
    finally:
        conn.close()
        time.sleep(1)
        

# Function to insert file
def insert_file(cursor, filepath: str):
    try:
        logging.info(f"Inserting file: {filepath}")

        checksum_hash = hashlib.sha512()
        file_data = bytearray()

        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                checksum_hash.update(chunk)
                file_data.extend(chunk)

        checksum = checksum_hash.hexdigest()

        cursor.execute(
            "INSERT INTO files (filename, filedata, checksum) VALUES (?, ?, ?)",
            (os.path.basename(filepath), file_data, checksum)
        )

        logging.info(f"Inserted file {filepath} with checksum {checksum}")

    except Exception as e:
        logging.error(f"Error inserting file {filepath}: {e}")

def extract_files(destination: str):
    try:
        logging.info(f"Extracting files to destination: {destination}")
        if not os.path.exists(destination):
            os.makedirs(destination)

        with sqlite3.connect("vaultr.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT filename, filedata, checksum FROM files")
            rows = cursor.fetchall()

            for row in rows:
                filename, filedata, checksum = row
                file_path = os.path.join(destination, filename)
                logging.info(f"Extracting file: {file_path}")
                try:
                    with open(file_path, "wb") as f:
                        f.write(filedata)
                    f.close()

                    checksum_hash = hashlib.sha512()
                    with open(file_path, "rb") as f:
                        while chunk := f.read(4096):
                            checksum_hash.update(chunk)
                    f.close()

                    current_checksum = checksum_hash.hexdigest()
                    if current_checksum != checksum:
                        logging.warning(f"Checksum mismatch for {filename}: "
                                        f"Stored: {checksum}, Current: {current_checksum}")
                        continue

                    logging.info(f"Successfully extracted file: {file_path}")
                except Exception as e:
                    logging.error(f"Error extracting file {filename}: {e}")
                    continue
        conn.close()
        logging.info("All files extracted successfully.")

    except Exception as e:
        logging.error(f"Error extracting files: {e}")

# Encrypt file
def encrypt_file(source: str, destination: str, password: str):
    try:
        logging.info(f"Encrypting files from source: {source}")
        initialize_package()

        if not os.path.isdir(source):
            logging.error(f"Source {source} is not a directory.")
            return

        with sqlite3.connect("vaultr.db") as conn:
            cursor = conn.cursor()
            for root, _, files in os.walk(source):
                full_paths = [os.path.join(root, file) for file in files]
                # Sort by creation time (oldest to newest)
                full_paths.sort(key=lambda x: os.path.getctime(x))
                for filepath in full_paths:
                    insert_file(cursor, filepath)
            conn.commit()
        logging.info("All files inserted into the database.")
        conn.close()
        time.sleep(1)  

        salt = os.urandom(16)  
        nonce = os.urandom(12)   
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        with open("vaultr.db", "rb") as f:
            data = f.read()
        f.close()

        encrypted_data = aesgcm.encrypt(nonce, data, None)
        encrypted_content = salt + nonce + encrypted_data

        base_name = os.path.basename(os.path.normpath(source))
        enc_file_name = base_name + ".enc"
        enc_file_path = os.path.join(destination, enc_file_name)

        if not os.path.exists(destination):
            os.makedirs(destination)

        with open(enc_file_path, "wb") as f:
            f.write(encrypted_content)
        f.close()

        logging.info(f"File encrypted successfully: {enc_file_path}")

    except Exception as e:
        logging.error(f"Error encrypting file: {e}")

    finally:
        try:
            time.sleep(1)  
            os.remove("vaultr.db")
            logging.info("Temporary database file removed.")
        except Exception as ex:
            logging.error(f"Error removing temporary database: {ex}")

# Decrypt file
def decrypt_file(source: str, destination: str, password: str):
    try:
        logging.info(f"Decrypting file: {source}")
        if not source.endswith(".enc"):
            logging.error("Source file is not an encrypted file (.enc).")
            return
        
        if not os.path.exists(source):
            logging.error(f"Source file {source} does not exist.")
            return
        
        with open(source, "rb") as f:
            content = f.read()
        f.close()

        salt = content[:16]   
        nonce = content[16:28]   
        encrypted_data = content[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        except Exception:
            logging.error("Decryption failed. Invalid password or corrupted file.")
            return

        with open("vaultr.db", "wb") as f:
            f.write(decrypted_data)
        f.close()

        extraction_dir = os.path.join(destination, os.path.basename(source).replace(".enc", ""))
        if not os.path.exists(extraction_dir):
            os.makedirs(extraction_dir)
        
        extract_files(extraction_dir)

        print(f"File decrypted: {destination}")
    except Exception as e:
        logging.error(f"Error decrypting file: {e}")
        return
    finally:
        try:
            time.sleep(1)  
            os.remove("vaultr.db")
            logging.info("Temporary database file removed after decryption.")
        except Exception as ex:
            logging.error(f"Error removing temporary database: {ex}")

# Simple CLI
def main():
    if len(sys.argv) != 5:
        print("Usage:")
        print("  Encrypt: python file_crypto.py encrypt <source> <destination> <password>")
        print("  Decrypt: python file_crypto.py decrypt <source> <destination> <password>")
        return

    action, source, destination, password = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    if action == "encrypt":
        encrypt_file(source, destination, password)
    elif action == "decrypt":
        decrypt_file(source, destination, password)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
