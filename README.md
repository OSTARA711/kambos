# KAMBOS File Encryptor

**KAMBOS** is a Linux desktop application for password-based file encryption and decryption. It uses **Argon2id** for password-based key derivation and **AES-256-GCM** for authenticated encryption, with a graphical interface built using GTK3.

KAMBOS stores encrypted files in its native **RINN v2** format, using the `.rinn` file extension.

## Features

* **Authenticated File Encryption:** AES-256-GCM provides confidentiality and detects unauthorised modifications to encrypted data.
* **Password-Based Key Derivation:** Argon2id derives encryption keys from user-supplied passwords.
* **RINN v2 File Format:** Stores the cryptographic parameters, salt, nonce and original filename alongside the encrypted content.
* **Original Filename Preservation:** Records the original filename, including its extension, so it can be suggested when decrypting.
* **GTK3 Graphical Interface:** Provides file selection, password entry and encryption/decryption workflows.
* **Linux Desktop Integration:** Supports integration with Linux desktop environments and `.rinn` file associations where configured.
* **Streaming File Processing:** Processes file contents in chunks rather than requiring the entire file to be held in memory.
* **Authenticated Decryption:** Decrypted content is kept in a temporary file until authentication succeeds. Failed authentication must not publish the decrypted output.

## Requirements

* Linux
* GCC or another compatible C compiler
* GTK3 development libraries
* libsodium development libraries
* OpenSSL development libraries
* `pkg-config`

On Debian- and Ubuntu-based distributions, install the development dependencies with:

```bash
sudo apt update
sudo apt install build-essential pkg-config libgtk-3-dev libsodium-dev libssl-dev
```

## Build from Source

Clone the repository and enter the project directory:

```bash
git clone https://github.com/OSTARA711/kambos.git
cd kambos
```

Compile KAMBOS:

```bash
gcc -Wall -Wextra -Wpedantic -O2 \
    -o kambos kambos.c \
    $(pkg-config --cflags --libs gtk+-3.0) \
    -lsodium -lssl -lcrypto -pthread
```

Launch the application:

```bash
./kambos
```

## Usage

### Encrypt a file

1. Launch KAMBOS.
2. Select the file to encrypt.
3. Enter a strong password.
4. Choose where to save the encrypted output.
5. Save the encrypted file with the `.rinn` extension.

### Decrypt a file

1. Open KAMBOS and select the encrypted `.rinn` file.
2. Enter the password used during encryption.
3. Choose where to save the recovered file.
4. Confirm that the recovered file matches the original where appropriate.

The original filename is stored in the encrypted file's authenticated metadata. It can be used to suggest a filename during decryption.

## RINN v2 Format and Cryptography

RINN v2 stores a versioned header containing cryptographic parameters and filename metadata, followed by the encrypted file contents and an authentication tag.

The current implementation uses:

* **Key derivation:** Argon2id via libsodium.
* **Encryption:** AES-256-GCM via OpenSSL.
* **Authentication:** The GCM authentication tag protects the encrypted content and authenticated header.
* **File processing:** Chunked input/output to support large files.
* **Decryption safety:** Provisional plaintext is written to a temporary file and is published only after successful authentication.

The cryptographic parameters needed for key derivation are stored in the file header. The implementation validates these parameters before using them.

The `.rinn` extension identifies the file type used by KAMBOS; it is not, by itself, a guarantee of authenticity or safety.

## Security Considerations

* Use a strong, unique password. Weak passwords can be vulnerable to offline guessing.
* Keep passwords confidential. Anyone who obtains the encrypted file and guesses its password may be able to recover its contents.
* Preserve backups of important files.
* Authentication detects unauthorised modifications; it does not establish who created a file or guarantee that the decrypted file is safe to open.
* KAMBOS should not be described as a ransomware detector unless a separate, implemented and tested detection mechanism is added.

## Development

KAMBOS is written in C and uses GTK3, libsodium and OpenSSL.

The project is under active development. Features and security properties should be considered subject to change until the implementation, automated tests and release process have been reviewed.

## Future Plans

Potential future work includes:

* Automated encryption/decryption regression tests.
* Expanded testing of malformed files, authentication failures and filesystem edge cases.
* Improved Linux desktop integration and packaging.
* Ubuntu PPA distribution.
* Optional integration with the system keyring for password management, subject to a security review.
* Evaluation of additional enterprise and batch-processing workflows.
