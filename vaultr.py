import argparse
import os
import sys
import hashlib
import sqlite3
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
import logging
from datetime import datetime, timezone, timedelta
from enum import Enum, auto

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs\\vaultr-{datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d')}.log"),
        logging.StreamHandler()
    ]
)

class CryptographyAlgorithm(Enum):
    PBKDF2 = auto()
    ARGON2ID = auto()

def derive_key(password: str, salt: bytes, algorithm: CryptographyAlgorithm = CryptographyAlgorithm.PBKDF2) -> bytes:
    if algorithm == CryptographyAlgorithm.PBKDF2:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
    elif algorithm == CryptographyAlgorithm.ARGON2ID:
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=2, 
            memory_cost=256 * 1024,
        )
    else:
        raise ValueError("Unsupported KDF algorithm")

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
        os.makedirs(destination, exist_ok=True)

        with sqlite3.connect("vaultr.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT filename, filedata, checksum FROM files")
            rows = cursor.fetchall()
            for filename, filedata, checksum in rows:
                file_path = os.path.join(destination, filename)
                logging.info(f"Extracting file: {file_path}")

                current_checksum = hashlib.sha512(filedata).hexdigest()
                if current_checksum != checksum:
                    logging.warning(f"Checksum mismatch for {filename}: Stored: {checksum}, Current: {current_checksum}")
                    continue

                try:
                    with open(file_path, "wb") as f:
                        f.write(filedata)
                    f.close()
                    logging.info(f"Successfully extracted file: {file_path}")
                except Exception as e:
                    logging.error(f"Error extracting file {filename}: {e}")
        conn.close()
        logging.info("All files extracted successfully.")

    except Exception as e:
        logging.error(f"Error extracting files: {e}")

def hashed_name(base_name: str, chunk_number: int) -> str:
    raw = f"{base_name}_{chunk_number:05d}".encode()
    return hashlib.sha1(raw).hexdigest()

def split_encrypted_file_with_padding(encrypted_content: bytes, destination: str, original_base_name: str, chunk_size: int = 512 * 1024):
    os.makedirs(destination, exist_ok=True)

    master_hash = hashlib.sha1(original_base_name.encode() + encrypted_content).digest()

    total_parts = (len(encrypted_content) + chunk_size - 1) // chunk_size

    for i in range(total_parts):
        start = i * chunk_size
        end = start + chunk_size
        chunk = encrypted_content[start:end]

        try:
            if len(chunk) < chunk_size:
                pad_len = chunk_size - len(chunk) - 4  
                if pad_len >= 0:
                    padding = os.urandom(pad_len)
                    chunk += padding + pad_len.to_bytes(4, 'big')
        except Exception as e:
            logging.error(f"Error during padding: {e}")
            continue

        hashed_filename = hashed_name(original_base_name, i + 1)
        part_path = os.path.join(destination, hashed_filename + ".dat")

        with open(part_path, "wb") as f:
            f.write(master_hash)
            f.write(chunk)
        f.close()

    logging.info(f"Encrypted file split into {total_parts} padded parts at '{destination}'")

def encrypt_data(source: str, destination: str, password: str):
    try:
        logging.info(f"Encrypting files from source: {source}")
        initialize_package()

        if not os.path.isdir(source):
            logging.error(f"Source {source} is not a directory.")
            return

        with sqlite3.connect("vaultr.db") as conn:
            cursor = conn.cursor()
            conn.execute("BEGIN")
            for root, _, files in os.walk(source):
                full_paths = [os.path.join(root, file) for file in files]
                full_paths.sort(key=lambda x: os.path.getctime(x))
                for filepath in full_paths:
                    insert_file(cursor, filepath)
            conn.commit()
        logging.info("All files inserted into the database.")
        conn.close()
        time.sleep(1) 

            
        with open("vaultr.db", "rb") as f:
            db_data = f.read()
        f.close()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        base_name = os.path.basename(os.path.normpath(source))
        final_salt = hashlib.sha256(salt + base_name.encode()).digest()
        key = derive_key(password, final_salt)
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, db_data, None)
        encrypted_content = salt + nonce + encrypted_data

        final_destination = os.path.join(destination, hashlib.sha1((base_name + "_secure" + str(time.time())).encode()).hexdigest())
        split_encrypted_file_with_padding(encrypted_content, final_destination, base_name)
        logging.info(f"File encrypted successfully at '{final_destination}'")
        
    except Exception as e:
        logging.error(f"Error encrypting file: {e}")

    finally:
        try:
            time.sleep(1)  
            os.remove("vaultr.db")
            logging.info("Temporary database file removed.")
        except Exception as ex:
            logging.error(f"Error removing temporary database: {ex}")

def decrypt_data(source: str, destination: str, password: str, chunk_size: int = 512 * 1024):
    try:
        original_base_name = os.path.basename(os.path.normpath(destination))

        assembled = bytearray()
        expected_hash = None
        part_num = 1

        while True:
            hashed = hashed_name(original_base_name, part_num)
            part_path = os.path.join(source, hashed + ".dat")

            if not os.path.exists(part_path):
                break  # No more parts

            with open(part_path, "rb") as f:
                content = f.read()
            f.close()

            if len(content) < 20:
                logging.error(f"Part {part_num} corrupted or incomplete.")
                return

            master_hash = content[:20]
            chunk_data = content[20:]

            if expected_hash is None:
                expected_hash = master_hash
            elif master_hash != expected_hash:
                logging.error(f"Hash mismatch detected in part {part_num}.")
                return

            assembled.extend(chunk_data)
            part_num += 1

        if part_num == 1:
            logging.error("No parts found to reassemble.")
            return
       
        if len(assembled) < 4:
             raise ValueError("Data too short to contain padding footer.")

        pad_len = int.from_bytes(assembled[-4:], 'big')
        if 0 <= pad_len <= chunk_size - 4:
            assembled = assembled[:-pad_len - 4]
        else:
            raise ValueError(f"Invalid pad length: {pad_len}")
        
        encrypted_content = assembled
        recomputed_hash = hashlib.sha1((original_base_name).encode() + encrypted_content).digest()

        if expected_hash != recomputed_hash:
            logging.error("Final integrity check failed, aborting.")
            return

        salt = bytes(encrypted_content[:16])
        nonce = bytes(encrypted_content[16:28])
        ciphertext = bytes(encrypted_content[28:])

        final_salt = hashlib.sha256(salt + original_base_name.encode()).digest()

        key = derive_key(password, final_salt)
        aesgcm = AESGCM(key)

        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

        with open("vaultr.db", "wb") as f:
            f.write(decrypted_data)
        f.close()

        os.makedirs(destination, exist_ok=True)
        extract_files(destination)
        os.remove("vaultr.db")

        logging.info(f"Decryption successful. Files extracted to '{destination}'")

    except Exception as e:
        logging.error(f"Error during decryption: {e}")

def main():
    parser = argparse.ArgumentParser(description="VaultR - Secure File Encryptor")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Choose to encrypt or decrypt files")
    parser.add_argument("source", help="Source directory or encrypted file path")
    parser.add_argument("destination", help="Destination directory to save output")
    parser.add_argument("password", help="Password for encryption/decryption")

    args = parser.parse_args()

    if args.action == "encrypt":
        encrypt_data(args.source, args.destination, args.password)
    elif args.action == "decrypt":
        decrypt_data(args.source, args.destination, args.password)

if __name__ == "__main__":
    main()
