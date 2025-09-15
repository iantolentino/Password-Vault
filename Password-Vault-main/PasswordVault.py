import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel
from tkinter import ttk
import logging

# ==============================
# Logging Setup
# ==============================
logging.basicConfig(
    filename="vault.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ==============================
# Database Setup
# ==============================
conn = sqlite3.connect("vault.db")
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

# ==============================
# Utility Functions
# ==============================

def bring_to_front(window):
    """Force a popup window to appear in front and grab focus."""
    window.lift()
    window.focus_force()
    window.attributes("-topmost", True)
    window.after(100, lambda: window.attributes("-topmost", False))

def center_window(window, width, height):
    """Center a window on the screen with the given width and height."""
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

def get_master():
    """Fetch the master password hash and encryption key from the database."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, key FROM master WHERE id=1")
    result = cursor.fetchone()
    conn.close()
    return result

def set_master(password, key):
    """Store the master password hash and encryption key on first setup."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO master (id, password_hash, key) VALUES (1, ?, ?)", (hashed, key.decode()))
    conn.commit()
    conn.close()
    logging.info("Master password and encryption key set.")

def add_entry(site, username, password, fernet):
    """Encrypt and store a new credential entry in the database."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    encrypted = fernet.encrypt(password.encode())
    cursor.execute("INSERT INTO vault (site, username, password_encrypted) VALUES (?, ?, ?)",
                   (site, username, encrypted.decode()))
    conn.commit()
    conn.close()
    logging.info(f"Added entry: Site={site}, Username={username}")

def get_entries(fernet):
    """Retrieve all stored entries and decrypt their passwords (used internally)."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password_encrypted FROM vault")
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1], row[2], fernet.decrypt(row[3].encode()).decode()) for row in rows]

def delete_entry(entry_id):
    """Delete an entry from the database using its ID."""
    conn = sqlite3.connect("vault.db")
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
# GUI / Theming Helpers
# ==============================

# Minimalist theme colors for light & dark
THEMES = {
    "light": {
        "bg": "#f6f7fb",
        "fg": "#0f1724",
        "card": "#ffffff",
        "button_bg": "#e6eef9",
        "accent": "#2563eb"
    },
    "dark": {
        "bg": "#0f1724",
        "fg": "#e6eef9",
        "card": "#15202b",
        "button_bg": "#243447",
        "accent": "#60a5fa"
    }
}

def apply_theme(root, style, theme_name="light"):
    """Apply color theme to main widgets and ttk styles."""
    t = THEMES[theme_name]
    root.configure(bg=t["bg"])
    style.configure("Card.TFrame", background=t["card"])
    style.configure("Main.TLabel", background=t["card"], foreground=t["fg"], font=("Segoe UI", 10))
    style.configure("Title.TLabel", background=t["bg"], foreground=t["accent"], font=("Segoe UI", 14, "bold"))
    style.configure("Rounded.TButton",
                    background=t["button_bg"],
                    foreground=t["fg"],
                    relief="flat",
                    padding=8,
                    font=("Segoe UI", 10, "normal"))
    # ttk Buttons don't accept background on some platforms; use style map for active state
    style.map("Rounded.TButton",
              foreground=[("active", t["fg"])],
              background=[("active", t["accent"])])

# ==============================
# GUI Application
# ==============================
class VaultApp:
    """Main application class that manages the Tkinter GUI and vault operations."""

    def __init__(self, master, fernet):
        self.master = master
        self.fernet = fernet
        self.theme = "light"

        # ttk style
        self.style = ttk.Style(master)
        # use clam for better styling on many platforms
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        apply_theme(master, self.style, self.theme)

        self.master.title("Password Vault")
        center_window(self.master, 540, 420)

        # Main container card
        self.container = ttk.Frame(master, style="Card.TFrame", padding=(16, 12, 16, 12))
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        # Title row
        title = ttk.Label(self.container, text="Password Vault", style="Title.TLabel")
        title.pack(anchor="w", pady=(0, 8))

        # Buttons frame
        btn_frame = ttk.Frame(self.container, style="Card.TFrame")
        btn_frame.pack(fill="x", pady=(0, 10))

        self.add_btn = ttk.Button(btn_frame, text="Add Entry", style="Rounded.TButton", command=self.add_entry_ui)
        self.add_btn.pack(side="left", padx=(0, 8))

        self.del_btn = ttk.Button(btn_frame, text="Delete Entry", style="Rounded.TButton", command=self.delete_entry_ui)
        self.del_btn.pack(side="left", padx=(0, 8))

        self.show_btn = ttk.Button(btn_frame, text="Show Password", style="Rounded.TButton", command=self.show_entry_ui)
        self.show_btn.pack(side="left", padx=(0, 8))

        self.theme_btn = ttk.Button(btn_frame, text="Toggle Theme", style="Rounded.TButton", command=self.toggle_theme)
        self.theme_btn.pack(side="right")

        # Entries list area (minimalist card-list)
        self.list_frame = ttk.Frame(self.container, style="Card.TFrame")
        self.list_frame.pack(fill="both", expand=True)

        # Use a Canvas+Frame to allow scrolling when many entries
        self.canvas = tk.Canvas(self.list_frame, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar = ttk.Scrollbar(self.list_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.entries_internal = ttk.Frame(self.canvas, style="Card.TFrame")
        self.canvas.create_window((0, 0), window=self.entries_internal, anchor="nw")

        self.entries_internal.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # Populate
        self.refresh_entries()

    def toggle_theme(self):
        """Switch between light and dark themes."""
        self.theme = "dark" if self.theme == "light" else "light"
        apply_theme(self.master, self.style, self.theme)
        # update immediate widget backgrounds/text
        self.refresh_entries()

    def refresh_entries(self):
        """Refresh the display area to show all stored credentials (only metadata)."""
        # clear children
        for widget in self.entries_internal.winfo_children():
            widget.destroy()

        entries = get_entries(self.fernet)
        if not entries:
            lbl = ttk.Label(self.entries_internal, text="No credentials saved yet.", style="Main.TLabel")
            lbl.pack(pady=8)
            return

        # For each entry show a minimalist rounded-like row (frame with label + small ID badge)
        for entry in entries:
            eid, site, username, _ = entry
            row = ttk.Frame(self.entries_internal, style="Card.TFrame", padding=(8,6))
            row.pack(fill="x", pady=6, padx=6)

            # ID badge
            badge = tk.Label(row, text=f"{eid}", width=4, anchor="center",
                             bg=THEMES[self.theme]["button_bg"], fg=THEMES[self.theme]["fg"], bd=0)
            badge.pack(side="left", padx=(0,8))

            text = ttk.Label(row, text=f"{site}  |  {username}", style="Main.TLabel")
            text.pack(side="left", padx=(0,8))

            # small "reveal" hint button (does not reveal directly)
            hint_btn = ttk.Button(row, text="View", style="Rounded.TButton",
                                  command=lambda _id=eid: self.show_single_entry(_id))
            hint_btn.pack(side="right")

    # ----------------------
    # Popups (all auto-destroy on completion)
    # ----------------------
    def add_entry_ui(self):
        """Open a popup to add entry (single form). Popup closes automatically after Save."""
        popup = Toplevel(self.master)
        popup.transient(self.master)
        popup.title("Add Entry")
        center_window(popup, 360, 220)
        popup.grab_set()
        bring_to_front(popup)

        # Use simple grid layout
        lbl_site = ttk.Label(popup, text="Site:")
        lbl_site.grid(row=0, column=0, sticky="w", padx=12, pady=(14,4))
        site_entry = ttk.Entry(popup, width=36)
        site_entry.grid(row=0, column=1, padx=12, pady=(14,4))

        lbl_user = ttk.Label(popup, text="Username:")
        lbl_user.grid(row=1, column=0, sticky="w", padx=12, pady=4)
        user_entry = ttk.Entry(popup, width=36)
        user_entry.grid(row=1, column=1, padx=12, pady=4)

        lbl_pass = ttk.Label(popup, text="Password:")
        lbl_pass.grid(row=2, column=0, sticky="w", padx=12, pady=4)
        pass_entry = ttk.Entry(popup, width=36, show="*")
        pass_entry.grid(row=2, column=1, padx=12, pady=4)

        def save_entry():
            site = site_entry.get().strip()
            username = user_entry.get().strip()
            password = pass_entry.get().strip()
            if site and username and password:
                add_entry(site, username, password, self.fernet)
                popup.destroy()      # auto-remove popup
                self.refresh_entries()
            else:
                messagebox.showwarning("Warning", "All fields are required.")

        save_btn = ttk.Button(popup, text="Save", style="Rounded.TButton", command=save_entry)
        save_btn.grid(row=3, column=0, columnspan=2, pady=(12,14))

    def delete_entry_ui(self):
        """Open a popup to delete an entry by ID. Popup closes after action."""
        popup = Toplevel(self.master)
        popup.transient(self.master)
        popup.title("Delete Entry")
        center_window(popup, 320, 140)
        popup.grab_set()
        bring_to_front(popup)

        lbl = ttk.Label(popup, text="Entry ID to delete:")
        lbl.pack(pady=(12,6))
        id_entry = ttk.Entry(popup, width=12)
        id_entry.pack()

        def do_delete():
            try:
                eid = int(id_entry.get().strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid numeric ID.")
                return
            delete_entry(eid)
            logging.info(f"Requested delete for ID={eid}")
            popup.destroy()
            self.refresh_entries()

        btn = ttk.Button(popup, text="Delete", style="Rounded.TButton", command=do_delete)
        btn.pack(pady=12)

    def show_entry_ui(self):
        """Open a popup to input ID to view. Popup closes after viewing or cancel."""
        popup = Toplevel(self.master)
        popup.transient(self.master)
        popup.title("Show Password")
        center_window(popup, 320, 150)
        popup.grab_set()
        bring_to_front(popup)

        lbl = ttk.Label(popup, text="Entry ID to view:")
        lbl.pack(pady=(12,6))
        id_entry = ttk.Entry(popup, width=12)
        id_entry.pack()

        def do_show():
            try:
                eid = int(id_entry.get().strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid numeric ID.")
                return

            # re-check master password
            master_data = get_master()
            if not master_data:
                messagebox.showerror("Error", "No master password found.")
                popup.destroy()
                return
            stored_hash, _ = master_data
            pw = simpledialog.askstring("Verify", "Enter master password:", show="*")
            bring_to_front(popup)
            if not pw or not bcrypt.checkpw(pw.encode(), stored_hash):
                messagebox.showerror("Error", "Master password incorrect.")
                logging.warning("Failed attempt to view entry password.")
                return

            # fetch & decrypt
            conn = sqlite3.connect("vault.db")
            cursor = conn.cursor()
            cursor.execute("SELECT site, username, password_encrypted FROM vault WHERE id=?", (eid,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                messagebox.showerror("Error", f"No entry with ID {eid}.")
                return

            site, username, enc_pass = row
            try:
                decrypted = self.fernet.decrypt(enc_pass.encode()).decode()
            except Exception as e:
                decrypted = f"(Error decrypting: {e})"

            # Show info in a short-lived popup then auto-close it after a short time
            info = Toplevel(self.master)
            info.transient(self.master)
            info.title("Decrypted Password")
            center_window(info, 360, 160)
            info.grab_set()
            bring_to_front(info)

            lbl1 = ttk.Label(info, text=f"Site: {site}", style="Main.TLabel")
            lbl1.pack(pady=(8,2))
            lbl2 = ttk.Label(info, text=f"Username: {username}", style="Main.TLabel")
            lbl2.pack(pady=2)
            lbl3 = ttk.Label(info, text=f"Password: {decrypted}", style="Main.TLabel")
            lbl3.pack(pady=6)

            # copy button (puts password to clipboard) and a close button
            def copy_pw():
                self.master.clipboard_clear()
                self.master.clipboard_append(decrypted)
                messagebox.showinfo("Copied", "Password copied to clipboard (clear after usage).")
                logging.info(f"Copied password for ID={eid} to clipboard.")

            btn_frame = ttk.Frame(info)
            btn_frame.pack(pady=(6,10))
            copy_btn = ttk.Button(btn_frame, text="Copy", style="Rounded.TButton", command=copy_pw)
            copy_btn.pack(side="left", padx=(0,6))
            close_btn = ttk.Button(btn_frame, text="Close", style="Rounded.TButton", command=info.destroy)
            close_btn.pack(side="left")

            # log view
            logging.info(f"Viewed entry password: ID={eid}, Site={site}, Username={username}")

            # close the "input id" popup (we're done)
            popup.destroy()

        btn = ttk.Button(popup, text="Show", style="Rounded.TButton", command=do_show)
        btn.pack(pady=12)

    def show_single_entry(self, eid):
        """Shortcut when pressing 'View' on a row: verifies master and shows single entry."""
        # re-check master password
        master_data = get_master()
        if not master_data:
            messagebox.showerror("Error", "No master password found.")
            return
        stored_hash, _ = master_data
        pw = simpledialog.askstring("Verify", "Enter master password:", show="*")
        bring_to_front(self.master)
        if not pw or not bcrypt.checkpw(pw.encode(), stored_hash):
            messagebox.showerror("Error", "Master password incorrect.")
            logging.warning("Failed attempt to view entry password.")
            return

        # fetch & decrypt
        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT site, username, password_encrypted FROM vault WHERE id=?", (eid,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            messagebox.showerror("Error", f"No entry with ID {eid}.")
            return

        site, username, enc_pass = row
        try:
            decrypted = self.fernet.decrypt(enc_pass.encode()).decode()
        except Exception as e:
            decrypted = f"(Error decrypting: {e})"

        # display brief popup with copy option
        info = Toplevel(self.master)
        info.transient(self.master)
        info.title("Decrypted Password")
        center_window(info, 360, 160)
        info.grab_set()
        bring_to_front(info)

        ttk.Label(info, text=f"Site: {site}", style="Main.TLabel").pack(pady=(8,2))
        ttk.Label(info, text=f"Username: {username}", style="Main.TLabel").pack(pady=2)
        ttk.Label(info, text=f"Password: {decrypted}", style="Main.TLabel").pack(pady=6)

        def copy_pw():
            self.master.clipboard_clear()
            self.master.clipboard_append(decrypted)
            messagebox.showinfo("Copied", "Password copied to clipboard (clear after usage).")
            logging.info(f"Copied password for ID={eid} to clipboard.")

        btn_frame = ttk.Frame(info)
        btn_frame.pack(pady=(6,10))
        ttk.Button(btn_frame, text="Copy", style="Rounded.TButton", command=copy_pw).pack(side="left", padx=(0,6))
        ttk.Button(btn_frame, text="Close", style="Rounded.TButton", command=info.destroy).pack(side="left")

        logging.info(f"Viewed entry password: ID={eid}, Site={site}, Username={username}")

# ==============================
# Main Program
# ==============================
def main():
    """Main entry point of the application: handles login/setup then starts GUI."""
    root = tk.Tk()
    root.withdraw()  # Hide main window until login/setup is done

    master_data = get_master()

    if master_data is None:
        pw = simpledialog.askstring("Setup", "Create a master password:", show="*")
        bring_to_front(root)
        key = Fernet.generate_key()
        set_master(pw, key)
        fernet = Fernet(key)
    else:
        stored_hash, key = master_data
        while True:
            pw = simpledialog.askstring("Login", "Enter master password:", show="*")
            bring_to_front(root)
            if pw is None:
                # user cancelled
                return
            if bcrypt.checkpw(pw.encode(), stored_hash):
                fernet = Fernet(key.encode())
                logging.info("Master password accepted. Vault unlocked.")
                break
            else:
                messagebox.showerror("Error", "Wrong master password. Try again.")
                logging.warning("Failed login attempt.")

    root.deiconify()  # Show main window after login
    app = VaultApp(root, fernet)
    root.mainloop()

if __name__ == "__main__":
    main()
