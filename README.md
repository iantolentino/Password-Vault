# 🔐 Password Vault

A secure, minimalistic **password manager with a Tkinter GUI**, built in Python.  
It allows you to safely store, retrieve, and manage credentials using **bcrypt hashing** and **AES-256 encryption (via Fernet)**.  

This project demonstrates professional coding practices, GUI development, database design, and cryptographic security.

---

## ✨ Features

- **Master Password Protection**  
  First-time setup requires a master password. This is stored as a `bcrypt` hash.

- **Encrypted Storage**  
  All saved passwords are encrypted with a unique **Fernet key (AES-256)**.

- **User-Friendly GUI (Tkinter + ttk)**  
  - Light/Dark theme toggle  
  - Minimalist, responsive UI with scrollable entry list  
  - Popup dialogs for add/view/delete actions  

- **Clipboard Integration**  
  Easily copy a decrypted password to clipboard (auto-clear recommendation).

- **Logging System**  
  Tracks logins, additions, deletions, and copy actions in `vault.log`.

- **SQLite Database**  
  Stores master password (hashed), encryption key, and credential entries.

---

## 🛠️ Tech Stack

- **Python 3.8+**
- `sqlite3` – secure local database
- `bcrypt` – hashing master password
- `cryptography.fernet` – AES-256 symmetric encryption
- `tkinter` & `ttk` – GUI with theming
- `logging` – activity and security event logging

---

## 📦 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/password-vault.git
   cd password-vault
  ```
````

2. Install dependencies:

   ```bash
   pip install bcrypt cryptography
   ```

3. Run the application:

   ```bash
   python vault.py
   ```

---

## 🚀 Usage

1. **First Run**

   * You’ll be prompted to create a master password.
   * A unique Fernet encryption key will be generated and stored securely.

2. **Add Credentials**

   * Click **"Add Entry"**, fill in site, username, and password.
   * Entry is encrypted and saved to SQLite.

3. **View Credentials**

   * Select "View" or "Show Password".
   * Re-enter master password for security.
   * Password is decrypted and displayed.

4. **Delete Credentials**

   * Provide the entry ID and delete securely.

5. **Toggle Theme**

   * Switch between **light and dark modes** dynamically.

---

## 🔐 Security Notes

* Master password is **hashed with bcrypt** and never stored in plain text.
* Passwords are encrypted using **AES-256 (via Fernet)**.
* Sensitive operations (view, copy) require re-entering master password.
* All actions are logged in `vault.log` for auditing.

⚠️ This app is intended for educational/demo use.
For production, additional security hardening is recommended (e.g., key derivation, secure clipboard clearing).

---

## 📂 Project Structure

```
vault.py          # Main application entry point
vault.db          # SQLite database (auto-created on first run)
vault.log         # Log file (auto-generated)
```

---

## 🤝 Contributing

Contributions are welcome!

* Follow **PEP 8** style guide.
* Use clear docstrings and inline comments.
* Open issues or PRs for improvements (UI, encryption, testing).

---

## 📝 License

MIT License © 2025 \[Ian Tolenntino]

---

## 💡 Future Improvements

* Auto-clear clipboard after a timeout.
* Export/Import encrypted backups.
* Password generator integration.
* Unit tests with `pytest`.

