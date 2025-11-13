# KAMBOS File Encryptor

**KAMBOS** is a secure file encryption and ransomware detection tool for Linux, using **Argon2id Key Derivation Function (KDF)** and **AES-256** encryption. It provides a GTK3-based graphical interface for ease of use and integrates with Linux desktop environments via MIME types.

---

## Features

- **Secure File Encryption**: Uses AES-256 in GCM mode for authenticated encryption.
- **Strong Key Derivation**: Argon2id KDF ensures secure keys from user passwords.
- **Ransomware Detection**: Uses HMAC-SHA256 and Poly1305-AES for message authentication to detect tampering.
- **GTK3 GUI**: Simple, intuitive interface for encrypting/decrypting files.
- **MIME Integration**: Registers `.rinn` files with your desktop environment for easy opening.
- **Cross-Desktop Compatibility**: Works on GNOME, XFCE (Thunar), and other Linux desktops.

---

## Usage

Launch KAMBOS from your application menu.

To encrypt a file: select it, provide a password, and save it as .rinn.

To decrypt: select a .rinn file, provide the password, and recover the original file.

The .rinn file format is associated with KAMBOS for double-click opening.

## Development Notes

Written in C, GTK3, using libsodium and OpenSSL.

Uses Argon2id KDF + AES-256-GCM for encryption.

HMAC-SHA256 and Poly1305-AES are used for authentication and ransomware detection.

Handles both file dialogs and drag-and-drop operations in GTK3.

Logs and errors are printed to the terminal; GUI shows success/failure messages.

## Future Plans

Full integration with system tray for quick encryption.

Advanced ransomware detection heuristics.

PPA release for Ubuntu-based distributions.

Secure password caching using system keyring.
