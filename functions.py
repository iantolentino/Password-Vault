"""
Utility functions for the Password Vault application
"""
import sqlite3
import bcrypt
import os
import shutil
import logging
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, filedialog, messagebox  # Added ttk import

# ==============================
# File Path Configuration
# ==============================
VAULT_DIR = r"Projects_Aug-Oct\Password-Vault-main\deepseek\credentials"
DB_PATH = os.path.join(VAULT_DIR, "vault.db")
LOG_PATH = os.path.join(VAULT_DIR, "vault.log")

def ensure_vault_directory():
    """Ensure the vault directory exists"""
    try:
        if not os.path.exists(VAULT_DIR):
            os.makedirs(VAULT_DIR)
            logging.info(f"Created vault directory: {VAULT_DIR}")
        return True
    except Exception as e:
        logging.error(f"Failed to create vault directory: {e}")
        return False

# ==============================
# Database Operations
# ==============================

def init_database():
    """Initialize database with required tables"""
    if not ensure_vault_directory():
        raise Exception(f"Could not create vault directory: {VAULT_DIR}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY,
        password_hash TEXT NOT NULL,
        key TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT NOT NULL,
        username TEXT NOT NULL,
        password_encrypted TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()
    logging.info("Database initialized")

def get_master():
    """Fetch the master password hash and encryption key from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, key FROM master WHERE id=1")
    result = cursor.fetchone()
    conn.close()
    return result

def set_master(password, key):
    """Store the master password hash and encryption key on first setup."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO master (id, password_hash, key) VALUES (1, ?, ?)", 
                  (hashed, key.decode()))
    conn.commit()
    conn.close()
    logging.info("Master password and encryption key set.")

def add_entry(site, username, password, fernet):
    """Encrypt and store a new credential entry in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    encrypted = fernet.encrypt(password.encode())
    cursor.execute("INSERT INTO vault (site, username, password_encrypted) VALUES (?, ?, ?)",
                   (site, username, encrypted.decode()))
    conn.commit()
    conn.close()
    logging.info(f"Added entry: Site={site}, Username={username}")

def get_entries(fernet):
    """Retrieve all stored entries and decrypt their passwords."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password_encrypted FROM vault")
    rows = cursor.fetchall()
    conn.close()
    
    decrypted_entries = []
    for row in rows:
        try:
            decrypted_password = fernet.decrypt(row[3].encode()).decode()
            decrypted_entries.append((row[0], row[1], row[2], decrypted_password))
        except Exception as e:
            logging.error(f"Error decrypting entry {row[0]}: {e}")
            # Keep encrypted password if decryption fails
            decrypted_entries.append((row[0], row[1], row[2], "[Decryption Error]"))
    
    return decrypted_entries

def delete_entry(entry_id):
    """Delete an entry from the database using its ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT site, username FROM vault WHERE id=?", (entry_id,))
    target = cursor.fetchone()
    cursor.execute("DELETE FROM vault WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()
    if target:
        logging.info(f"Deleted entry: Site={target[0]}, Username={target[1]}")
    else:
        logging.warning(f"Tried to delete non-existing entry ID={entry_id}")

# ==============================
# Import/Export Operations
# ==============================

def export_vault(export_path=None):
    """Export the vault database to a specified location"""
    try:
        if export_path is None:
            export_path = filedialog.asksaveasfilename(
                defaultextension=".db",
                filetypes=[("Database files", "*.db"), ("All files", "*.*")],
                title="Export Vault Database"
            )
        
        if export_path:
            shutil.copy2(DB_PATH, export_path)
            logging.info(f"Vault exported to: {export_path}")
            return True, f"Vault successfully exported to:\n{export_path}"
        return False, "Export cancelled"
    except Exception as e:
        logging.error(f"Export failed: {e}")
        return False, f"Export failed: {str(e)}"

def import_vault(import_path=None):
    """Import a vault database from a specified location"""
    try:
        if import_path is None:
            import_path = filedialog.askopenfilename(
                filetypes=[("Database files", "*.db"), ("All files", "*.*")],
                title="Import Vault Database"
            )
        
        if import_path:
            # Backup current database
            if os.path.exists(DB_PATH):
                backup_path = DB_PATH + ".backup"
                shutil.copy2(DB_PATH, backup_path)
            
            # Replace with imported database
            shutil.copy2(import_path, DB_PATH)
            logging.info(f"Vault imported from: {import_path}")
            return True, f"Vault successfully imported from:\n{import_path}\n\nPrevious database backed up as: {backup_path}"
        return False, "Import cancelled"
    except Exception as e:
        logging.error(f"Import failed: {e}")
        return False, f"Import failed: {str(e)}"

def get_file_paths():
    """Get absolute paths of vault files"""
    return DB_PATH, LOG_PATH

# ==============================
# Window Utilities
# ==============================

def center_window(window, width=None, height=None):
    """Center a window on the screen"""
    if width is None or height is None:
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
    
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    window.geometry(f"{width}x{height}+{x}+{y}")

def bring_to_front(window):
    """Bring window to front and grab focus"""
    window.lift()
    window.focus_force()
    window.attributes("-topmost", True)
    window.after(100, lambda: window.attributes("-topmost", False))

def create_rounded_entry(parent, style='Modern.TEntry', **kwargs):
    """Create a modern-looking entry widget"""
    entry = ttk.Entry(parent, style=style, **kwargs)  # Fixed: ttk is now imported
    return entry

def validate_master_password(password):
    """Validate master password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password is too long (max 128 characters)"
    
    # Check for basic complexity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase letters and numbers"
    
    return True, "Password is strong"