"""
Main Password Vault Application - Simplified Version
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import logging
import bcrypt
from cryptography.fernet import Fernet
import os
import sys
import traceback
import sqlite3
from datetime import datetime

# ==============================
# Database Functions
# ==============================
def get_db_path():
    """Get database path in user's home directory"""
    home_dir = os.path.expanduser("~")
    vault_dir = os.path.join(home_dir, ".password_vault")
    os.makedirs(vault_dir, exist_ok=True)
    return os.path.join(vault_dir, "vault.db")

def get_log_path():
    """Get log file path"""
    home_dir = os.path.expanduser("~")
    vault_dir = os.path.join(home_dir, ".password_vault")
    os.makedirs(vault_dir, exist_ok=True)
    return os.path.join(vault_dir, "vault.log")

def init_database():
    """Initialize the database"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create master password table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            encryption_key TEXT NOT NULL
        )
    ''')
    
    # Create entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_master():
    """Get master password data"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash, encryption_key FROM master_password LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    
    return result

def set_master(password, encryption_key):
    """Set master password"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Hash the password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    # Clear any existing master password
    cursor.execute("DELETE FROM master_password")
    
    # Insert new master password
    cursor.execute(
        "INSERT INTO master_password (password_hash, encryption_key) VALUES (?, ?)",
        (password_hash, encryption_key.decode())
    )
    
    conn.commit()
    conn.close()

def add_entry(site, username, password, fernet):
    """Add a new entry"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    encrypted_password = fernet.encrypt(password.encode()).decode()
    
    cursor.execute(
        "INSERT INTO entries (site, username, password_encrypted) VALUES (?, ?, ?)",
        (site, username, encrypted_password)
    )
    
    conn.commit()
    conn.close()

def get_entries(fernet):
    """Get all entries"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, site, username, password_encrypted FROM entries ORDER BY site")
    entries = cursor.fetchall()
    conn.close()
    
    # Decrypt passwords
    decrypted_entries = []
    for entry in entries:
        try:
            decrypted_password = fernet.decrypt(entry[3].encode()).decode()
            decrypted_entries.append((entry[0], entry[1], entry[2], decrypted_password))
        except:
            # If decryption fails, keep encrypted version
            decrypted_entries.append((entry[0], entry[1], entry[2], "***ENCRYPTED***"))
    
    return decrypted_entries

def delete_entry(entry_id):
    """Delete an entry"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

def export_vault():
    """Export vault database"""
    try:
        db_path = get_db_path()
        home_dir = os.path.expanduser("~")
        export_path = os.path.join(home_dir, "vault_backup.db")
        
        import shutil
        shutil.copy2(db_path, export_path)
        return True, f"Vault exported to: {export_path}"
    except Exception as e:
        return False, f"Export failed: {str(e)}"

def import_vault():
    """Import vault database"""
    try:
        db_path = get_db_path()
        home_dir = os.path.expanduser("~")
        import_path = os.path.join(home_dir, "vault_backup.db")
        
        if not os.path.exists(import_path):
            return False, "Backup file not found in home directory"
        
        import shutil
        shutil.copy2(import_path, db_path)
        return True, "Vault imported successfully"
    except Exception as e:
        return False, f"Import failed: {str(e)}"

def validate_master_password(password):
    """Validate master password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        return False, "Password must contain both uppercase and lowercase letters"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    return True, "Strong password"

# ==============================
# Utility Functions
# ==============================
def center_window(window, width=800, height=600):
    """Center the window on screen"""
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    window.geometry(f"{width}x{height}+{x}+{y}")

def bring_to_front(window):
    """Bring window to front"""
    window.lift()
    window.attributes('-topmost', True)
    window.after_idle(window.attributes, '-topmost', False)

def get_file_paths():
    """Get file paths for display"""
    return get_db_path(), get_log_path()

# ==============================
# Simple Password Dialog
# ==============================
def create_password_dialog(parent, title, is_setup=False):
    """Create a simple password dialog"""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.grab_set()
    dialog.resizable(False, False)
    
    # Set size and center
    height = 280 if is_setup else 200
    center_window(dialog, 400, height)
    bring_to_front(dialog)
    
    result = {"password": None}
    
    # Main frame
    main_frame = tk.Frame(dialog, padx=20, pady=20)
    main_frame.pack(fill="both", expand=True)
    
    # Title
    tk.Label(main_frame, text=title, font=("Arial", 12, "bold")).pack(pady=(0, 20))
    
    # Password entry
    tk.Label(main_frame, text="Enter Password:", anchor="w").pack(fill="x", pady=(0, 5))
    password_entry = tk.Entry(main_frame, show="*", width=30, font=("Arial", 10))
    password_entry.pack(fill="x", pady=(0, 15))
    password_entry.focus()
    
    # Confirm password (for setup)
    confirm_entry = None
    if is_setup:
        tk.Label(main_frame, text="Confirm Password:", anchor="w").pack(fill="x", pady=(0, 5))
        confirm_entry = tk.Entry(main_frame, show="*", width=30, font=("Arial", 10))
        confirm_entry.pack(fill="x", pady=(0, 15))
    
    # Buttons
    button_frame = tk.Frame(main_frame)
    button_frame.pack(fill="x", pady=(20, 0))
    
    def on_ok():
        password = password_entry.get()
        
        if is_setup and confirm_entry:
            confirm = confirm_entry.get()
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return
            
            # Validate password strength
            is_valid, message = validate_master_password(password)
            if not is_valid:
                messagebox.showerror("Weak Password", message)
                return
        
        if password:
            result["password"] = password
            dialog.destroy()
        else:
            messagebox.showwarning("Warning", "Please enter a password")
    
    def on_cancel():
        dialog.destroy()
    
    # Buttons
    tk.Button(button_frame, text="Cancel", command=on_cancel, width=10).pack(side="left", padx=(0, 10))
    tk.Button(button_frame, text="OK", command=on_ok, width=10).pack(side="right")
    
    # Bind Enter key
    password_entry.bind('<Return>', lambda e: on_ok())
    if confirm_entry:
        confirm_entry.bind('<Return>', lambda e: on_ok())
    
    # Wait for dialog
    parent.wait_window(dialog)
    return result["password"]

# ==============================
# Add Entry Dialog
# ==============================
class AddEntryDialog:
    def __init__(self, parent, on_save):
        self.on_save = on_save
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Add New Entry")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)
        
        center_window(self.dialog, 400, 280)
        bring_to_front(self.dialog)
        
        self.setup_ui()
    
    def setup_ui(self):
        main_frame = tk.Frame(self.dialog, padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title
        tk.Label(main_frame, text="Add New Credential", font=("Arial", 12, "bold")).pack(pady=(0, 20))
        
        # Site
        tk.Label(main_frame, text="Site/App:", anchor="w").pack(fill="x", pady=(0, 5))
        self.site_entry = tk.Entry(main_frame, width=30, font=("Arial", 10))
        self.site_entry.pack(fill="x", pady=(0, 15))
        
        # Username
        tk.Label(main_frame, text="Username/Email:", anchor="w").pack(fill="x", pady=(0, 5))
        self.user_entry = tk.Entry(main_frame, width=30, font=("Arial", 10))
        self.user_entry.pack(fill="x", pady=(0, 15))
        
        # Password
        tk.Label(main_frame, text="Password:", anchor="w").pack(fill="x", pady=(0, 5))
        self.pass_entry = tk.Entry(main_frame, width=30, show="*", font=("Arial", 10))
        self.pass_entry.pack(fill="x", pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        
        def on_save_click():
            site = self.site_entry.get().strip()
            username = self.user_entry.get().strip()
            password = self.pass_entry.get().strip()
            
            if site and username and password:
                self.on_save(site, username, password)
                self.dialog.destroy()
            else:
                messagebox.showwarning("Warning", "All fields are required!")
        
        tk.Button(button_frame, text="Cancel", command=self.dialog.destroy, width=10).pack(side="left", padx=(0, 10))
        tk.Button(button_frame, text="Save", command=on_save_click, width=10).pack(side="right")
        
        self.site_entry.focus()

# ==============================
# Main Application
# ==============================
class VaultApp:
    def __init__(self, root, fernet):
        self.root = root
        self.fernet = fernet
        
        self.setup_window()
        self.setup_ui()
        self.refresh_entries()
    
    def setup_window(self):
        self.root.title("Password Vault")
        self.root.geometry("800x600")
        center_window(self.root, 800, 600)
    
    def setup_ui(self):
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(header_frame, text="🔐 Password Vault", font=("Arial", 16, "bold")).pack(side="left")
        
        # Action buttons
        action_frame = tk.Frame(header_frame)
        action_frame.pack(side="right")
        
        tk.Button(action_frame, text="➕ Add Entry", command=self.add_entry, 
                 width=12).pack(side="left", padx=(5, 5))
        tk.Button(action_frame, text="📤 Export", command=self.export_vault,
                 width=10).pack(side="left", padx=(5, 5))
        tk.Button(action_frame, text="📥 Import", command=self.import_vault,
                 width=10).pack(side="left", padx=(5, 0))
        
        # File paths
        paths_frame = tk.LabelFrame(main_frame, text=" File Locations ", padx=10, pady=10)
        paths_frame.pack(fill="x", pady=(0, 20))
        
        db_path, log_path = get_file_paths()
        tk.Label(paths_frame, text=f"Database: {db_path}", anchor="w").pack(fill="x")
        tk.Label(paths_frame, text=f"Log File: {log_path}", anchor="w").pack(fill="x")
        
        # Entries list
        list_frame = tk.LabelFrame(main_frame, text=" Stored Credentials ", padx=10, pady=10)
        list_frame.pack(fill="both", expand=True)
        
        # Create a frame for the list with scrollbar
        list_container = tk.Frame(list_frame)
        list_container.pack(fill="both", expand=True)
        
        # Create treeview for entries
        columns = ("ID", "Site", "Username", "Actions")
        self.tree = ttk.Treeview(list_container, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.tree.heading("ID", text="ID")
        self.tree.heading("Site", text="Site/Application")
        self.tree.heading("Username", text="Username/Email")
        self.tree.heading("Actions", text="Actions")
        
        self.tree.column("ID", width=50)
        self.tree.column("Site", width=200)
        self.tree.column("Username", width=250)
        self.tree.column("Actions", width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind double-click to view entry
        self.tree.bind("<Double-1>", self.on_entry_double_click)
    
    def refresh_entries(self):
        """Refresh the entries list"""
        # Clear existing entries
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        entries = get_entries(self.fernet)
        
        if not entries:
            # Add a placeholder for empty state
            self.tree.insert("", "end", values=("", "No entries yet", "Click 'Add Entry' to start", ""))
            return
        
        # Add entries to treeview
        for entry in entries:
            eid, site, username, _ = entry
            self.tree.insert("", "end", values=(eid, site, username, "Double-click to view"))
    
    def on_entry_double_click(self, event):
        """Handle double-click on entry"""
        item = self.tree.selection()[0]
        values = self.tree.item(item, "values")
        entry_id = values[0]
        
        if entry_id:  # Make sure it's not the placeholder
            self.show_entry_details(int(entry_id))
    
    def add_entry(self):
        """Add new entry"""
        AddEntryDialog(self.root, self.save_entry)
    
    def save_entry(self, site, username, password):
        """Save new entry callback"""
        add_entry(site, username, password, self.fernet)
        self.refresh_entries()
        messagebox.showinfo("Success", "Entry added successfully!")
    
    def show_entry_details(self, entry_id):
        """Show entry details"""
        # Verify master password first
        if not self.verify_master_password():
            return
        
        entries = get_entries(self.fernet)
        target_entry = None
        
        for entry in entries:
            if entry[0] == entry_id:
                target_entry = entry
                break
        
        if not target_entry:
            messagebox.showerror("Error", "Entry not found")
            return
        
        _, site, username, password = target_entry
        
        # Show details in a dialog
        details_dialog = tk.Toplevel(self.root)
        details_dialog.title("Credential Details")
        details_dialog.transient(self.root)
        details_dialog.grab_set()
        details_dialog.resizable(False, False)
        
        center_window(details_dialog, 400, 300)
        bring_to_front(details_dialog)
        
        main_frame = tk.Frame(details_dialog, padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title
        tk.Label(main_frame, text="🔍 Credential Details", font=("Arial", 12, "bold")).pack(pady=(0, 20))
        
        # Site
        tk.Label(main_frame, text="Site/App:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x")
        tk.Label(main_frame, text=site, font=("Arial", 10), anchor="w").pack(fill="x", pady=(0, 15))
        
        # Username
        tk.Label(main_frame, text="Username/Email:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x")
        tk.Label(main_frame, text=username, font=("Arial", 10), anchor="w").pack(fill="x", pady=(0, 15))
        
        # Password
        tk.Label(main_frame, text="Password:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x")
        
        password_frame = tk.Frame(main_frame)
        password_frame.pack(fill="x", pady=(0, 20))
        
        password_var = tk.StringVar(value="•" * 12)
        password_label = tk.Label(password_frame, textvariable=password_var, font=("Arial", 12, "bold"))
        password_label.pack(side="left")
        
        def toggle_password():
            if password_var.get() == "•" * 12:
                password_var.set(password)
                toggle_btn.config(text="Hide")
            else:
                password_var.set("•" * 12)
                toggle_btn.config(text="Show")
        
        toggle_btn = tk.Button(password_frame, text="Show", command=toggle_password, width=8)
        toggle_btn.pack(side="right", padx=(10, 0))
        
        # Buttons
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        
        def copy_password():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        
        tk.Button(button_frame, text="Copy Password", command=copy_password, width=12).pack(side="left", padx=(0, 10))
        tk.Button(button_frame, text="Delete", command=lambda: self.delete_entry(entry_id, details_dialog), 
                 width=8).pack(side="left", padx=(0, 10))
        tk.Button(button_frame, text="Close", command=details_dialog.destroy, width=8).pack(side="right")
    
    def delete_entry(self, entry_id, parent_dialog=None):
        """Delete an entry"""
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            delete_entry(entry_id)
            self.refresh_entries()
            if parent_dialog:
                parent_dialog.destroy()
            messagebox.showinfo("Success", "Entry deleted successfully!")
    
    def verify_master_password(self):
        """Verify master password"""
        master_data = get_master()
        if not master_data:
            messagebox.showerror("Error", "No master password found")
            return False
        
        password = create_password_dialog(self.root, "Verify Master Password")
        
        if password is None:
            return False
        
        stored_hash, _ = master_data
        
        try:
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                return True
            else:
                messagebox.showerror("Error", "Incorrect master password")
                return False
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")
            return False
    
    def export_vault(self):
        """Export vault"""
        if messagebox.askyesno("Export", "Export vault database to your home directory?"):
            success, message = export_vault()
            if success:
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)
    
    def import_vault(self):
        """Import vault"""
        if messagebox.askyesno("Import", "WARNING: This will replace your current vault!\nContinue?"):
            success, message = import_vault()
            if success:
                messagebox.showinfo("Success", message)
                # Restart application
                self.root.destroy()
                main()
            else:
                messagebox.showerror("Error", message)

# ==============================
# Main Program
# ==============================
def setup_logging():
    """Setup logging"""
    log_path = get_log_path()
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info("Password Vault started")

def main():
    """Main entry point"""
    print("Starting Password Vault...")
    
    # Setup logging
    setup_logging()
    
    # Create root window
    root = tk.Tk()
    
    try:
        # Initialize database
        init_database()
        logging.info("Database initialized")
    except Exception as e:
        logging.error(f"Database init failed: {e}")
        messagebox.showerror("Error", f"Failed to initialize database: {e}")
        root.destroy()
        return
    
    # Check for master password
    master_data = get_master()
    fernet = None
    
    if master_data is None:
        # First-time setup
        print("First-time setup required")
        password = create_password_dialog(root, "Setup Master Password", is_setup=True)
        
        if password is None:
            print("Setup cancelled")
            root.destroy()
            return
        
        try:
            # Set master password
            key = Fernet.generate_key()
            set_master(password, key)
            fernet = Fernet(key)
            logging.info("Master password set")
            messagebox.showinfo("Success", "Master password set successfully!")
        except Exception as e:
            logging.error(f"Failed to set master password: {e}")
            messagebox.showerror("Error", f"Failed to set master password: {e}")
            root.destroy()
            return
    else:
        # Login with existing master password
        stored_hash, key = master_data
        
        for attempt in range(3):
            password = create_password_dialog(root, "Login to Vault")
            
            if password is None:
                print("Login cancelled")
                root.destroy()
                return
            
            try:
                if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                    fernet = Fernet(key.encode())
                    logging.info("Login successful")
                    break
                else:
                    if attempt < 2:
                        messagebox.showerror("Error", f"Wrong password. {2-attempt} attempts left.")
                    else:
                        messagebox.showerror("Error", "Too many failed attempts. Exiting.")
                        root.destroy()
                        return
            except Exception as e:
                logging.error(f"Login error: {e}")
                messagebox.showerror("Error", f"Login failed: {e}")
                root.destroy()
                return
    
    # Start main application
    if fernet:
        try:
            app = VaultApp(root, fernet)
            logging.info("Main application started")
            root.mainloop()
        except Exception as e:
            logging.error(f"Application error: {e}")
            messagebox.showerror("Error", f"Application error: {e}")
    else:
        root.destroy()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")
