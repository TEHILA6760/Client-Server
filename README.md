# Defensive Client-Server File Transfer System

A secure and defensive client-server file transfer system implemented in C++ (Client) and Python (Server). This project is built with a focus on robust defensive programming, hybrid encryption, custom binary protocols, and state persistence for crash recovery.

---

## 📂 Project Architecture & Structure

The repository is organized into two main modules:
* **Client/** – C++ (Visual Studio / C++20) Client Implementation
* **Server/** – Python 3 Server Implementation with SQLite Persistence

* **Server (`Server/`):** Manages client registrations, handles multiple incoming connections (using threads/selectors), processes encrypted file streams, verifies file integrity via CRC32, and persists state into an SQLite database (`defensive.db`).
* **Client (`Client/`):** Operates in batch mode using configuration files (`transfer.json`), performs key exchange (RSA & AES via Crypto++), sends encrypted payloads, and handles error recovery and retransmissions.

---

## 🔒 Core Defensive Features & Security Mechanisms

### Custom Binary Protocol
* Built strictly over TCP using **Little-Endian** byte ordering for all numerical fields.
* Defined request and response packet structures (including registration `825`, public key exchange `826`, file transmission, and CRC verification codes `900`-`902`).

### Hybrid Encryption
* **Asymmetric Encryption:** RSA key generation and exchange.
* **Symmetric Encryption:** AES encryption for protecting file payloads and data streams via the **Crypto++** library (Client) and standard Python libraries (Server).

### Data Integrity & Persistence
* **CRC32 Validation:** Ensures file integrity across transfers with up to 3 automated retries upon failure.
* **SQLite Database (`defensive.db`):** Stores user registries, public keys, session states, and received file metadata, enabling seamless crash recovery and resumption without re-registering.

---

## 🚀 Getting Started

### 1. Running the Server (Python)
Navigate to the `Server` directory and run the main script:
```bash
python main.py
