Defensive Client-Server File Transfer System

A secure and defensive client-server file transfer system implemented in C++ (Client) and Python (Server). This project is built with a focus on robust defensive programming, hybrid encryption, custom binary protocols, and state persistence for crash recovery.

🏗️ Project Architecture & Structure

The repository is organized into two main modules:

├── Client/         # C++ (Visual Studio / C++20) Client Implementation
├── Server/         # Python 3 Server Implementation with SQLite Persistence
└── README.md


Server (Server/): Manages client registrations, handles multiple incoming connections (using threads/selectors), processes encrypted file streams, verifies file integrity via CRC32, and persists state into an SQLite database (defensive.db).

Client (Client/): Operates in batch mode using configuration files (transfer.json), performs key exchange (RSA & AES via Crypto++), sends encrypted payloads, and handles error recovery and retransmissions.

🔒 Core Defensive Features & Security Mechanics

Custom Binary Protocol:

Built strictly over TCP using Little-Endian byte ordering for all numerical fields.

Fixed and variable-size packets for requests (codes: 825 registration, 826 public key, 827 reconnect, 828 file send, 900-902 CRC verification status) and server responses.

Hybrid Encryption:

Asymmetric encryption (RSA) for secure public key exchange.

Symmetric encryption (AES) via Crypto++ (client) and standard Python libraries for high-performance file transfer encryption.

Data Integrity & Retransmission:

Automatic CRC32 checksum calculation and verification between client and server.

Built-in retry mechanism (up to 3 retransmissions) if integrity validation fails.

Crash Recovery & Persistence (SQLite):

Server maintains an SQLite database (defensive.db) containing client records (clients table) and received files (files table) with a composite primary key (ID, FileName) to prevent data overwrites.

Enables seamless session recovery after server restarts without requiring re-registration.

Robust Configuration Management:

Server reads port configurations dynamically from port.info (with a safe fallback to default port 1369 and warnings instead of crashes).

Client reads execution and target parameters from transfer.json.

🚀 Getting Started & Execution

Prerequisites

Client Side: Visual Studio (supporting C++20), Boost Asio, and Crypto++ libraries.

Server Side: Python 3.12+ with standard libraries and PyCryptodome.

Running the Server

Navigate to the Server/ directory.

(Optional) Ensure port.info is present with your desired port number.

Run the main server script:

python main.py


Running the Client

Configure your target parameters in transfer.json (Server IP, Port, Client Name, and Target Files).

Compile and execute the C++ client project via Visual Studio.

🛡️ Research & Vulnerability Analysis

As part of the defensive systems evaluation, the project includes an analysis of potential threat vectors (such as Denial of Service [DoS], Man-in-the-Middle [MITM], and Replay Attacks) alongside mitigation strategies and secure coding practices.
