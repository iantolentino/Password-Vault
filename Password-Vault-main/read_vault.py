import sqlite3
import bcrypt
from cryptography.fernet import Fernet

# Connect to the local database file
conn = sqlite3.connect("vault.db")
cursor = conn.cursor()

print("=== Tables in vault.db ===")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print(cursor.fetchall())

print("\n=== Master Table ===")
cursor.execute("SELECT * FROM master")
master_row = cursor.fetchone()
if master_row:
    mid, password_hash, key = master_row
    print(f"Master ID: {mid}")
    print(f"Master Password Hash:\n{password_hash}")  # hashed master password
    print(f"Encryption Key:\n{key}")

    # Create Fernet for decrypting vault passwords
    fernet = Fernet(key.encode())
else:
    print("No master password set.")
    fernet = None

print("\n=== Vault Table ===")
cursor.execute("SELECT * FROM vault")
rows = cursor.fetchall()
if not rows:
    print("No entries found.")
else:
    for row in rows:
        vid, site, username, encrypted_password = row
        print(f"\nEntry ID: {vid}")
        print(f"Site: {site}")
        print(f"Username: {username}")
        # print(f"Encrypted Password: {encrypted_password}")

        # Decrypt password only if we have Fernet key
        if fernet:
            try:
                decrypted = fernet.decrypt(encrypted_password.encode()).decode()
                print(f"Decrypted Password: {decrypted}")
            except Exception as e:
                print(f"Could not decrypt: {e}")

    # === New Feature: Select by ID ===
    try:
        selected_id = int(input("\nEnter the Entry ID you want to view: "))
        cursor.execute("SELECT * FROM vault WHERE id=?", (selected_id,))
        selected_row = cursor.fetchone()

        if selected_row:
            vid, site, username, encrypted_password = selected_row
            print("\n=== Selected Entry ===")
            print(f"Entry ID: {vid}")
            print(f"Site: {site}")
            print(f"Username: {username}")
            print(f"Encrypted Password: {encrypted_password}")

            if fernet:
                try:
                    decrypted = fernet.decrypt(encrypted_password.encode()).decode()
                    print(f"Decrypted Password: {decrypted}")
                except Exception as e:
                    print(f"Could not decrypt: {e}")
        else:
            print("No entry found with that ID.")
    except ValueError:
        print("Invalid input. Please enter a numeric ID.")

conn.close()
