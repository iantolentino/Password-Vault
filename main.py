"""
Main Password Vault Application
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import logging
import bcrypt
from cryptography.fernet import Fernet

# Import from our modules
from style import configure_styles, apply_dark_theme, create_modern_button, create_card_frame, DARK_THEME
from functions import (init_database, get_master, set_master, add_entry, 
                      get_entries, delete_entry, export_vault, import_vault, 
                      get_file_paths, center_window, bring_to_front, 
                      create_rounded_entry, validate_master_password, LOG_PATH, ensure_vault_directory)

# ==============================
# Logging Setup with Custom Path
# ==============================
def setup_logging():
    """Setup logging with the custom path"""
    if ensure_vault_directory():
        logging.basicConfig(
            filename=LOG_PATH,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info("Logging initialized")
    else:
        # Fallback to current directory if custom path fails
        logging.basicConfig(
            filename="vault.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.warning(f"Could not create vault directory, using fallback location")

# ==============================
# Modern Popup Dialogs
# ==============================
class ModernDialog:
    """Base class for modern dialogs"""
    
    def __init__(self, parent, title, width=400, height=200):
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.configure(bg=DARK_THEME['primary_bg'])
        self.dialog.resizable(False, False)
        
        # Apply dark theme
        apply_dark_theme(self.dialog)
        
        # Center dialog
        center_window(self.dialog, width, height)
        bring_to_front(self.dialog)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup UI - to be implemented by subclasses"""
        pass

class PasswordDialog(ModernDialog):
    """Dialog for master password input with strength validation"""
    
    def __init__(self, parent, title, is_setup=False):
        self.is_setup = is_setup
        self.password = None
        height = 300 if is_setup else 200
        super().__init__(parent, title, 450, height)  # Fixed: call parent __init__ only once
    
    def setup_ui(self):
        card = create_card_frame(self.dialog, 20)
        card.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(card, text="Master Password", style='Title.TLabel').pack(pady=(0, 20))
        
        # Password entry
        ttk.Label(card, text="Enter Password:", style='Normal.TLabel').pack(anchor='w', pady=(0, 5))
        self.pass_entry = create_rounded_entry(card, width=35, show="*")
        self.pass_entry.pack(fill='x', pady=(0, 10))
        self.pass_entry.bind('<KeyRelease>', self.on_password_change)
        
        # Confirm password (for setup)
        if self.is_setup:
            ttk.Label(card, text="Confirm Password:", style='Normal.TLabel').pack(anchor='w', pady=(0, 5))
            self.confirm_entry = create_rounded_entry(card, width=35, show="*")
            self.confirm_entry.pack(fill='x', pady=(0, 10))
            self.confirm_entry.bind('<KeyRelease>', self.on_password_change)
        
        # Strength indicator
        self.strength_frame = ttk.Frame(card, style='Card.TFrame')
        self.strength_frame.pack(fill='x', pady=(0, 10))
        
        self.strength_label = ttk.Label(self.strength_frame, text="", style='Normal.TLabel')
        self.strength_label.pack(anchor='w')
        
        # Requirements list (for setup)
        if self.is_setup:
            requirements_frame = ttk.Frame(card, style='Card.TFrame')
            requirements_frame.pack(fill='x', pady=(0, 15))
            
            ttk.Label(requirements_frame, text="Password Requirements:", style='Subtitle.TLabel').pack(anchor='w')
            self.req1 = ttk.Label(requirements_frame, text="✓ At least 8 characters", style='Normal.TLabel')
            self.req1.pack(anchor='w')
            self.req2 = ttk.Label(requirements_frame, text="✓ Uppercase and lowercase letters", style='Normal.TLabel')
            self.req2.pack(anchor='w')
            self.req3 = ttk.Label(requirements_frame, text="✓ At least one number", style='Normal.TLabel')
            self.req3.pack(anchor='w')
        
        # Buttons
        btn_frame = ttk.Frame(card, style='Card.TFrame')
        btn_frame.pack(fill='x', pady=(10, 0))
        
        create_modern_button(btn_frame, "Cancel", 
                           command=self.dialog.destroy, 
                           style='Secondary.TButton').pack(side='left', padx=(0, 10))
        
        self.ok_btn = create_modern_button(btn_frame, "OK", 
                           command=self.validate_and_accept, 
                           style='Primary.TButton')
        self.ok_btn.pack(side='right')
        
        self.pass_entry.focus()
        self.update_button_state()
    
    def on_password_change(self, event=None):
        """Handle password input changes"""
        self.update_button_state()
        
        if self.is_setup:
            password = self.pass_entry.get()
            is_valid, message = validate_master_password(password)
            
            # Update strength indicator
            if not password:
                self.strength_label.configure(text="")
            elif is_valid:
                self.strength_label.configure(text="✓ Strong password", foreground="#28a745")
            else:
                self.strength_label.configure(text=f"⚠ {message}", foreground="#ffc107")
            
            # Update requirements
            self.update_requirements()
    
    def update_requirements(self):
        """Update requirement checkmarks"""
        if not self.is_setup:
            return
            
        password = self.pass_entry.get()
        
        # Requirement 1: Length
        if len(password) >= 8:
            self.req1.configure(text="✓ At least 8 characters", foreground="#28a745")
        else:
            self.req1.configure(text="✗ At least 8 characters", foreground="#dc3545")
        
        # Requirement 2: Upper and lower case
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        if has_upper and has_lower:
            self.req2.configure(text="✓ Uppercase and lowercase letters", foreground="#28a745")
        else:
            self.req2.configure(text="✗ Uppercase and lowercase letters", foreground="#dc3545")
        
        # Requirement 3: Numbers
        has_digit = any(c.isdigit() for c in password)
        if has_digit:
            self.req3.configure(text="✓ At least one number", foreground="#28a745")
        else:
            self.req3.configure(text="✗ At least one number", foreground="#dc3545")
    
    def update_button_state(self):
        """Update OK button state based on input validity"""
        if self.is_setup:
            password = self.pass_entry.get()
            confirm = self.confirm_entry.get() if hasattr(self, 'confirm_entry') else ""
            is_valid, _ = validate_master_password(password)
            passwords_match = (password == confirm)
            
            self.ok_btn.configure(state="normal" if (is_valid and passwords_match) else "disabled")
        else:
            # For login, just check if password is not empty
            password = self.pass_entry.get()
            self.ok_btn.configure(state="normal" if password else "disabled")
    
    def validate_and_accept(self):
        """Validate input and accept if valid"""
        password = self.pass_entry.get()
        
        if self.is_setup:
            confirm = self.confirm_entry.get()
            
            # Validate strength
            is_valid, message = validate_master_password(password)
            if not is_valid:
                messagebox.showerror("Weak Password", message)
                return
            
            # Check if passwords match
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return
        
        self.password = password
        self.dialog.destroy()

class AddEntryDialog(ModernDialog):
    """Dialog for adding new entries"""
    
    def __init__(self, parent, on_save):
        self.on_save = on_save
        super().__init__(parent, "Add New Entry", 400, 280)
    
    def setup_ui(self):
        card = create_card_frame(self.dialog, 20)
        card.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(card, text="Add New Credential", style='Title.TLabel').pack(pady=(0, 20))
        
        # Site
        ttk.Label(card, text="Site/App:", style='Normal.TLabel').pack(anchor='w', pady=(0, 5))
        self.site_entry = create_rounded_entry(card, width=30)
        self.site_entry.pack(fill='x', pady=(0, 15))
        
        # Username
        ttk.Label(card, text="Username/Email:", style='Normal.TLabel').pack(anchor='w', pady=(0, 5))
        self.user_entry = create_rounded_entry(card, width=30)
        self.user_entry.pack(fill='x', pady=(0, 15))
        
        # Password
        ttk.Label(card, text="Password:", style='Normal.TLabel').pack(anchor='w', pady=(0, 5))
        self.pass_entry = create_rounded_entry(card, width=30, show="*")
        self.pass_entry.pack(fill='x', pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(card, style='Card.TFrame')
        btn_frame.pack(fill='x', pady=(10, 0))
        
        create_modern_button(btn_frame, "Cancel", 
                           command=self.dialog.destroy, 
                           style='Secondary.TButton').pack(side='left', padx=(0, 10))
        
        create_modern_button(btn_frame, "Save Entry", 
                           command=self.save_entry, 
                           style='Primary.TButton').pack(side='right')
        
        self.site_entry.focus()
    
    def save_entry(self):
        site = self.site_entry.get().strip()
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        
        if site and username and password:
            self.on_save(site, username, password)
            self.dialog.destroy()
        else:
            messagebox.showwarning("Warning", "All fields are required.")

# ==============================
# Main Application
# ==============================
class VaultApp:
    """Modern Password Vault Application"""
    
    def __init__(self, master, fernet):
        self.master = master
        self.fernet = fernet
        
        # Configure window
        self.master.title("Password Vault - Secure Credential Manager")
        self.master.configure(bg=DARK_THEME['primary_bg'])
        center_window(self.master, 800, 600)
        
        # Configure styles
        self.style = configure_styles(master)
        
        self.setup_ui()
        self.refresh_entries()
    
    def setup_ui(self):
        """Setup the main user interface"""
        # Main container with padding
        main_container = ttk.Frame(self.master, style='Main.TFrame', padding=20)
        main_container.pack(fill="both", expand=True)
        
        # Header
        header_frame = ttk.Frame(main_container, style='Main.TFrame')
        header_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Label(header_frame, text="🔐 Password Vault", style='Title.TLabel').pack(side='left')
        
        # Action buttons frame
        action_frame = ttk.Frame(header_frame, style='Main.TFrame')
        action_frame.pack(side='right')
        
        create_modern_button(action_frame, "➕ Add Entry", 
                           command=self.add_entry_ui, 
                           style='Primary.TButton').pack(side='left', padx=(5, 0))
        
        create_modern_button(action_frame, "📤 Export", 
                           command=self.export_vault_ui, 
                           style='Secondary.TButton').pack(side='left', padx=(5, 0))
        
        create_modern_button(action_frame, "📥 Import", 
                           command=self.import_vault_ui, 
                           style='Secondary.TButton').pack(side='left', padx=(5, 0))
        
        # File paths info
        self.setup_paths_info(main_container)
        
        # Entries list
        self.setup_entries_list(main_container)
    
    def setup_paths_info(self, parent):
        """Setup file paths information display"""
        paths_card = create_card_frame(parent, 15)
        paths_card.pack(fill="x", pady=(0, 20))
        
        db_path, log_path = get_file_paths()
        
        ttk.Label(paths_card, text="📁 File Locations:", style='Subtitle.TLabel').pack(anchor='w')
        ttk.Label(paths_card, text=f"Database: {db_path}", style='Normal.TLabel').pack(anchor='w', pady=(5, 0))
        ttk.Label(paths_card, text=f"Log File: {log_path}", style='Normal.TLabel').pack(anchor='w')
    
    def setup_entries_list(self, parent):
        """Setup the entries list display"""
        list_card = create_card_frame(parent, 0)
        list_card.pack(fill="both", expand=True)
        
        # List header
        header_frame = ttk.Frame(list_card, style='Card.TFrame', padding=(20, 15, 20, 15))
        header_frame.pack(fill="x")
        
        ttk.Label(header_frame, text="ID", style='Subtitle.TLabel', width=5).pack(side='left')
        ttk.Label(header_frame, text="Site/Application", style='Subtitle.TLabel', width=20).pack(side='left', padx=(0, 10))
        ttk.Label(header_frame, text="Username/Email", style='Subtitle.TLabel', width=25).pack(side='left', padx=(0, 10))
        ttk.Label(header_frame, text="Actions", style='Subtitle.TLabel').pack(side='right')
        
        # Separator
        separator = ttk.Frame(list_card, style='Border.TFrame', height=1)
        separator.pack(fill="x", padx=20)
        
        # Scrollable entries area
        list_container = ttk.Frame(list_card, style='Card.TFrame')
        list_container.pack(fill="both", expand=True, padx=20, pady=15)
        
        # Canvas with scrollbar for entries
        self.canvas = tk.Canvas(list_container, bg=DARK_THEME['card_bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.canvas.yview, style='Modern.Vertical.TScrollbar')
        self.scrollable_frame = ttk.Frame(self.canvas, style='Card.TFrame')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def refresh_entries(self):
        """Refresh the entries list"""
        # Clear existing entries
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        entries = get_entries(self.fernet)
        
        if not entries:
            # Show empty state
            empty_frame = ttk.Frame(self.scrollable_frame, style='Card.TFrame', padding=40)
            empty_frame.pack(fill="both", expand=True)
            
            ttk.Label(empty_frame, text="📭 No credentials stored yet", 
                     style='Subtitle.TLabel').pack()
            ttk.Label(empty_frame, text="Click 'Add Entry' to store your first credential", 
                     style='Normal.TLabel').pack(pady=(10, 0))
            return
        
        # Display entries
        for idx, entry in enumerate(entries):
            eid, site, username, _ = entry
            
            entry_frame = ttk.Frame(self.scrollable_frame, style='Card.TFrame', padding=(15, 10))
            entry_frame.pack(fill="x", pady=5)
            
            # Alternate background for better readability
            if idx % 2 == 0:
                entry_frame.configure(style='Card.TFrame')
            else:
                # Slightly different background for alternating rows
                temp_style = ttk.Style()
                temp_style.configure('AltCard.TFrame', background=DARK_THEME['tertiary_bg'])
                entry_frame.configure(style='AltCard.TFrame')
            
            # Entry data
            ttk.Label(entry_frame, text=str(eid), style='Normal.TLabel', width=5).pack(side='left')
            ttk.Label(entry_frame, text=site, style='Normal.TLabel', width=20).pack(side='left', padx=(0, 10))
            ttk.Label(entry_frame, text=username, style='Normal.TLabel', width=25).pack(side='left', padx=(0, 10))
            
            # Action buttons
            action_frame = ttk.Frame(entry_frame, style='Card.TFrame')
            action_frame.pack(side='right')
            
            create_modern_button(action_frame, "👁️ View", 
                               command=lambda eid=eid: self.show_single_entry(eid),
                               style='Secondary.TButton').pack(side='left', padx=(0, 5))
            
            create_modern_button(action_frame, "🗑️ Delete", 
                               command=lambda eid=eid: self.delete_entry_ui(eid),
                               style='Danger.TButton').pack(side='left')
    
    def add_entry_ui(self):
        """Open add entry dialog"""
        AddEntryDialog(self.master, self.add_entry)
    
    def add_entry(self, site, username, password):
        """Add new entry callback"""
        add_entry(site, username, password, self.fernet)
        self.refresh_entries()
        messagebox.showinfo("Success", "Entry added successfully!")
    
    def delete_entry_ui(self, entry_id):
        """Delete entry with confirmation"""
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete entry #{entry_id}?\nThis action cannot be undone."):
            delete_entry(entry_id)
            self.refresh_entries()
            messagebox.showinfo("Success", "Entry deleted successfully!")
    
    def show_single_entry(self, eid):
        """Show single entry details"""
        # Verify master password first
        if not self.verify_master_password():
            return
        
        entries = get_entries(self.fernet)
        target_entry = None
        
        for entry in entries:
            if entry[0] == eid:
                target_entry = entry
                break
        
        if not target_entry:
            messagebox.showerror("Error", f"No entry found with ID {eid}")
            return
        
        _, site, username, password = target_entry
        
        # Show entry details
        self.show_entry_details(site, username, password, eid)
    
    def verify_master_password(self):
        """Verify master password using modern dialog"""
        master_data = get_master()
        if not master_data:
            messagebox.showerror("Error", "No master password found.")
            return False
        
        dialog = PasswordDialog(self.master, "Verify Master Password", is_setup=False)
        self.master.wait_window(dialog.dialog)
        
        if dialog.password is None:
            return False  # User cancelled
        
        stored_hash, _ = master_data
        if not bcrypt.checkpw(dialog.password.encode(), stored_hash):
            messagebox.showerror("Error", "Master password incorrect.")
            logging.warning("Failed master password verification.")
            return False
        
        return True
    
    def show_entry_details(self, site, username, password, eid):
        """Show entry details in a dialog"""
        details_dialog = tk.Toplevel(self.master)
        details_dialog.title("Credential Details")
        details_dialog.transient(self.master)
        details_dialog.grab_set()
        details_dialog.configure(bg=DARK_THEME['primary_bg'])
        center_window(details_dialog, 400, 300)
        bring_to_front(details_dialog)
        
        card = create_card_frame(details_dialog, 25)
        card.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(card, text="🔍 Credential Details", style='Title.TLabel').pack(pady=(0, 20))
        
        # Site
        ttk.Label(card, text="Site/App:", style='Subtitle.TLabel').pack(anchor='w')
        ttk.Label(card, text=site, style='Normal.TLabel', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 15))
        
        # Username
        ttk.Label(card, text="Username/Email:", style='Subtitle.TLabel').pack(anchor='w')
        ttk.Label(card, text=username, style='Normal.TLabel', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 15))
        
        # Password
        ttk.Label(card, text="Password:", style='Subtitle.TLabel').pack(anchor='w')
        
        password_frame = ttk.Frame(card, style='Card.TFrame')
        password_frame.pack(fill='x', pady=(0, 20))
        
        password_label = ttk.Label(password_frame, text="•" * 12, style='Normal.TLabel', 
                                 font=('Segoe UI', 12, 'bold'))
        password_label.pack(side='left')
        
        def toggle_password():
            if password_label.cget('text') == "•" * 12:
                password_label.configure(text=password)
                toggle_btn.configure(text="🙈 Hide")
            else:
                password_label.configure(text="•" * 12)
                toggle_btn.configure(text="👁️ Show")
        
        toggle_btn = create_modern_button(password_frame, "👁️ Show", 
                                        command=toggle_password,
                                        style='Secondary.TButton')
        toggle_btn.pack(side='right', padx=(10, 0))
        
        # Action buttons
        btn_frame = ttk.Frame(card, style='Card.TFrame')
        btn_frame.pack(fill='x', pady=(10, 0))
        
        def copy_password():
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
            logging.info(f"Copied password for ID={eid}")
        
        create_modern_button(btn_frame, "📋 Copy Password", 
                           command=copy_password, 
                           style='Primary.TButton').pack(side='left', padx=(0, 10))
        
        create_modern_button(btn_frame, "Close", 
                           command=details_dialog.destroy, 
                           style='Secondary.TButton').pack(side='right')
    
    def export_vault_ui(self):
        """Export vault database"""
        if messagebox.askyesno("Export Vault", 
                             "This will create a backup copy of your vault database.\nContinue?"):
            success, message = export_vault()
            messagebox.showinfo("Export Result", message)
    
    def import_vault_ui(self):
        """Import vault database"""
        if messagebox.askyesno("Import Vault", 
                             "WARNING: This will replace your current vault database!\nMake sure you have a backup.\nContinue?"):
            success, message = import_vault()
            if success:
                messagebox.showinfo("Import Result", message)
                # Restart application
                self.master.destroy()
                main()
            else:
                messagebox.showerror("Import Failed", message)

# ==============================
# Main Program
# ==============================
def main():
    """Main entry point"""
    # Setup logging first
    setup_logging()
    
    root = tk.Tk()
    root.withdraw()  # Hide until setup complete
    
    try:
        # Initialize database (this will create the directory if needed)
        init_database()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to initialize vault: {e}")
        return
    
    # Check if master password exists
    master_data = get_master()
    
    if master_data is None:
        # First-time setup with improved password dialog
        setup_complete = False
        while not setup_complete:
            dialog = PasswordDialog(root, "Setup Master Password", is_setup=True)
            root.wait_window(dialog.dialog)
            
            if dialog.password is None:
                return  # User cancelled
            
            # Set master password
            key = Fernet.generate_key()
            set_master(dialog.password, key)
            fernet = Fernet(key)
            messagebox.showinfo("Setup Complete", "Master password set successfully!\n\nKeep your master password safe - it cannot be recovered if lost.")
            setup_complete = True
    else:
        # Existing user - verify password with improved dialog
        stored_hash, key = master_data
        login_successful = False
        
        while not login_successful:
            dialog = PasswordDialog(root, "Login to Vault", is_setup=False)
            root.wait_window(dialog.dialog)
            
            if dialog.password is None:
                return  # User cancelled
            
            if bcrypt.checkpw(dialog.password.encode(), stored_hash):
                fernet = Fernet(key.encode())
                logging.info("Master password accepted. Vault unlocked.")
                login_successful = True
            else:
                messagebox.showerror("Error", "Wrong master password. Try again.")
                logging.warning("Failed login attempt.")
    
    # Show main application
    root.deiconify()
    app = VaultApp(root, fernet)
    
    # Ensure window is centered
    root.after(100, lambda: center_window(root, 800, 600))
    
    root.mainloop()

if __name__ == "__main__":
    main()