# Defensive Client-Server File Transfer System

A secure and defensive client-server file transfer system implemented in C++ (Client) and Python (Server)[cite: 9]. This project focuses on robust defensive programming, hybrid encryption, custom binary protocols, and state persistence for crash recovery[cite: 9].

---

## 📂 Project Architecture & Structure

The repository is organized into two main modules:

```text
├── Server/
│   ├── main.py          # Server entry point (runs the core loop & handles connections)
│   └── protocol.py      # Binary protocol parser and request/response handler
└── Client/
    ├── main.cpp         # Client entry point (Visual Studio C++20)
    └── transfer.json    # Local configuration file (IP, Port, Client Name, Files)
```

---

## 🔒 Core Defensive Features & Security Mechanisms

### 1. Custom Binary Protocol
* Built strictly over TCP using **Little-Endian** byte ordering for all numerical fields.
* Defined request and response packet structures (including registration `825`, public key exchange `826`, file transfer `828`, and CRC verification codes `900`–`902`)[cite: 9].

### 2. Hybrid Encryption
* **Asymmetric Encryption:** RSA key pair generation and public key exchange[cite: 9].
* **Symmetric Encryption:** AES encryption for protecting file payloads via the **Crypto++** library (Client) and **PyCryptodome** (Server)[cite: 9].

### 3. Data Integrity & Persistence
* **CRC32 Validation:** Ensures file integrity across transfers with up to 3 automated retries upon failure[cite: 9].
* **SQLite Database (`defensive.db`):** Stores user registries (`clients` table), public keys, AES keys, and received file metadata (`files` table), enabling seamless crash recovery and resumption without re-registering[cite: 9, 10].

---

## 🚀 Getting Started & Execution Instructions

### Step 1: Setting up the Server (Python)
1. Navigate to the `Server` directory.
2. Ensure you have `main.py` and `protocol.py` in place.
3. Run the server from the terminal:
   ```bash
   python main.py
   ```
   *(Note: If `port.info` is missing, the server safely defaults to port `1369`).*

### Step 2: Setting up the Client (C++)
1. Open the `Client` project in **Visual Studio Community** (configured with C++20)[cite: 9].
2. Place your **`transfer.json`** configuration file in the execution directory, containing the server IP, port, client name, and target file paths[cite: 9].
3. Build and run the client project directly from **`main.cpp`** within Visual Studio.
