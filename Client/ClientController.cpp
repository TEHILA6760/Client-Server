#include "ClientController.h" 
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <algorithm>

constexpr uint8_t CLIENT_VERSION = 3;

namespace {
    // פונקציות עזר להמרה ל-Little Endian
    void writeUint16LE(std::vector<uint8_t>& buf, uint16_t val) {
        buf.push_back(static_cast<uint8_t>(val & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    }

    void writeUint32LE(std::vector<uint8_t>& buf, uint32_t val) {
        buf.push_back(static_cast<uint8_t>(val & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    }

    uint16_t readUint16LE(const uint8_t* buf) {
        return static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
    }

    uint32_t readUint32LE(const uint8_t* buf) {
        return static_cast<uint32_t>(buf[0]) |
            (static_cast<uint32_t>(buf[1]) << 8) |
            (static_cast<uint32_t>(buf[2]) << 16) |
            (static_cast<uint32_t>(buf[3]) << 24);
    }
}

ClientController::ClientController() : network(nullptr), serverPort(0) {
    clientId.assign(16, 0);
    clientName = "";
    filePath = "";
    serverIp = "";
}


ClientController::~ClientController() {
    if (network) {
        delete network;
        network = nullptr;
    }
}

void ClientController::fillPadding(std::vector<uint8_t>& vec, size_t targetSize) {
    if (vec.size() < targetSize) {
        vec.resize(targetSize, 0);
    }
}

bool ClientController::start() {
    // 1. טעינת הגדרות התקשורת מה-JSON
    if (!setupManager.loadTransferInfo("transfer.json")) {
        std::cerr << "ClientController Error: Failed to load transfer.json" << std::endl;
        return false;
    }

    serverIp = setupManager.getConfig().serverIp;
    serverPort = setupManager.getConfig().serverPort;
    clientName = setupManager.getConfig().clientName;
    filePath = setupManager.getConfig().filePath;

    std::cout << "Connecting to server " << serverIp << ":" << serverPort << "..." << std::endl;
    network = new Network(serverIp, serverPort);
    if (!network->connect()) {
        std::cerr << "ClientController Error: Connection to server failed." << std::endl;
        return false;
    }

    // 2. בדיקה אם הלקוח כבר רשום (קיום me.info ו-priv.key)
    bool isRegistered = setupManager.loadMeInfo("me.info") && setupManager.loadPrivateKey("priv.key");

    bool authSuccess = false;
    if (isRegistered) {
        std::cout << "Existing user found. Attempting reconnection..." << std::endl;

        const auto& identity = setupManager.getIdentity();
        clientId.assign(identity.clientId, identity.clientId + 16);
        privateKeyBase64 = identity.privateKey;

        authSuccess = handleReconnection();


        if (!authSuccess) {
            std::cout << "Reconnection failed/refused. Falling back to fresh registration..." << std::endl;
            clientId.assign(16, 0);
            authSuccess = handleRegistration();
        }
    }
    else {
        std::cout << "New client. Initiating registration..." << std::endl;
        authSuccess = handleRegistration();
    }

    if (!authSuccess) {
        std::cerr << "ClientController Error: Authentication / Key Exchange failed." << std::endl;
        return false;
    }

    // 3. הצפנת הקבצים ושליחתם בלולאה
    bool allSuccess = true;
    for (const auto& currentPath : setupManager.getConfig().filePaths) {
        this->filePath = currentPath; // עדכון נתיב הקובץ הנוכחי ברמת המחלקה

        std::cout << "Encrypting and sending file: " << this->filePath << "..." << std::endl;

        if (!sendEncryptedFile()) {
            std::cerr << "Error: Failed to send file: " << this->filePath << std::endl;
            allSuccess = false; // מסמן שגיאה אבל מאפשר להמשיך לקובץ הבא ברשימה
        }
    }

    network->disconnect();
    return allSuccess;
}

bool ClientController::handleRegistration() {
    // בקשה 825: הרשמה
    std::vector<uint8_t> packet;

    // Header (23 בתים)
    packet.insert(packet.end(), 16, 0); // Client ID מאופס
    packet.push_back(CLIENT_VERSION);   // 3
    writeUint16LE(packet, RequestCode::REGISTER); // 825
    writeUint32LE(packet, 255);        // Payload Size: 255 bytes for Name

    // Payload (255 בתים עבור השם)
    std::vector<uint8_t> nameBuf(clientName.begin(), clientName.end());
    fillPadding(nameBuf, 255);
    packet.insert(packet.end(), nameBuf.begin(), nameBuf.end());

    if (!network->sendData(packet)) {
        return false;
    }

    // קבלת תשובה (23 בתים Header)
    std::vector<uint8_t> responseHeader;
    if (!network->receiveData(responseHeader, 7)) {
        return false;
    }

    uint16_t code = readUint16LE(&responseHeader[1]);
    uint32_t payloadSize = readUint32LE(&responseHeader[3]);

    if (code == ResponseCode::REGISTER_SUCCESS) {
        std::vector<uint8_t> payload;
        if (!network->receiveData(payload, payloadSize)) {
            return false;
        }

        if (payload.size() >= 16) {
            clientId.assign(payload.begin(), payload.begin() + 16);
            std::string hexId = setupManager.bytesToHex(clientId);
            std::ofstream meFile("me.info");
            if (!meFile.is_open()) {
                std::cerr << "Fatal Error: Defensive check failed. me.info could not be created or accessed!" << std::endl;
                return false;
            }
            meFile << clientName << "\n" << hexId << "\n";
            meFile.close();
            setupManager.loadMeInfo("me.info");

            std::cout << "Registration successful! Assigned Client ID." << std::endl;
            return sendPublicKey();
        }

    }

    std::cerr << "Registration failed with response code: " << code << std::endl;
    return false;
}

bool ClientController::sendPublicKey() {
    // יצירת זוג מפתחות RSA
    std::vector<uint8_t> publicKeyBytes;
    if (!CryptoHandler::generateRsaKeyPair(privateKeyBase64, publicKeyBytes)) {
        return false;
    }
    std::cout << "Public key bytes size: " << publicKeyBytes.size() << std::endl;//בדיקת אורך המפתח הציבורי

    SetupManager::savePrivateKey("priv.key", privateKeyBase64);
    setupManager.saveMeInfo("me.info");


    // בקשה 826: שליחת מפתח ציבורי (255 בתים שם + 160 בתים מפתח)
    std::vector<uint8_t> packet;

    // Header (23 בתים)
    packet.insert(packet.end(), clientId.begin(), clientId.end());
    packet.push_back(CLIENT_VERSION);
    writeUint16LE(packet, RequestCode::SEND_PUBLIC_KEY); // 826

    std::vector<uint8_t> nameBuf(clientName.begin(), clientName.end());
    fillPadding(nameBuf, 255);

    uint32_t payloadSize = static_cast<uint32_t>(255 + publicKeyBytes.size());
    writeUint32LE(packet, payloadSize);

    // Payload
    packet.insert(packet.end(), nameBuf.begin(), nameBuf.end());
    packet.insert(packet.end(), publicKeyBytes.begin(), publicKeyBytes.end());

    if (!network->sendData(packet)) {
        return false;
    }

    // תשובת שרת (23 בתים Header)
    std::vector<uint8_t> responseHeader;
    if (!network->receiveData(responseHeader, 7)) {
        return false;
    }

    uint16_t code = readUint16LE(&responseHeader[1]);
    uint32_t resPayloadSize = readUint32LE(&responseHeader[3]);

    if (code == ResponseCode::PUBLIC_KEY_RECEIVED) {
        std::vector<uint8_t> payload;
        if (!network->receiveData(payload, resPayloadSize)) {
            return false;
        }

        // Payload מכיל: Client ID (16 בתים) + Encrypted AES key
        if (payload.size() > 16) {
            std::vector<uint8_t> encryptedAesKey(payload.begin() + 16, payload.end());
            if (CryptoHandler::decryptAesKey(privateKeyBase64, encryptedAesKey, aesKey)) {
                std::cout << "AES key successfully received and decrypted!" << std::endl;
                return true;
            }
        }
    }

    std::cerr << "Failed to receive AES key from server. Response code: " << code << std::endl;
    return false;
}

bool ClientController::handleReconnection() {
    // בקשה 827: התחברות מחדש
    std::vector<uint8_t> packet;

    packet.insert(packet.end(), clientId.begin(), clientId.end());
    packet.push_back(CLIENT_VERSION);
    writeUint16LE(packet, RequestCode::RECONNECT);// 827
    writeUint32LE(packet, 255);

    std::vector<uint8_t> nameBuf(clientName.begin(), clientName.end());
    fillPadding(nameBuf, 255);
    packet.insert(packet.end(), nameBuf.begin(), nameBuf.end());

    if (!network->sendData(packet)) {
        return false;
    }

    std::vector<uint8_t> responseHeader;
    if (!network->receiveData(responseHeader, 7)) {
        return false;
    }

    uint16_t code = readUint16LE(&responseHeader[1]);
    uint32_t payloadSize = readUint32LE(&responseHeader[3]);

    if (code == ResponseCode::RECONNECT_APPROVED) {
        std::vector<uint8_t> payload;
        if (!network->receiveData(payload, payloadSize)) {
            return false;
        }

        if (payload.size() > 16) {
            std::vector<uint8_t> encryptedAesKey(payload.begin() + 16, payload.end());
            if (CryptoHandler::decryptAesKey(privateKeyBase64, encryptedAesKey, aesKey)) {
                std::cout << "Reconnection successful! Decrypted AES key." << std::endl;
                return true;
            }
        }
    }

    std::cout << "Reconnection response code: " << code << " (refused/failed)" << std::endl;
    return false;
}

bool ClientController::sendEncryptedFile() {
    // 1. הצפנת הקובץ ב-AES
    std::vector<uint8_t> encryptedFile;
    if (!CryptoHandler::encryptFileAes(aesKey, filePath, encryptedFile)) {
        std::cerr << "Error: File encryption failed." << std::endl;
        return false;
    }

    // 2. חישוב CRC32 של קובץ המקור
    uint32_t origCrc = 0;
    if (!CryptoHandler::calculateCrc(filePath, origCrc)) {
        std::cerr << "Error: CRC calculation failed." << std::endl;
        return false;
    }

    uint32_t origFileSize = static_cast<uint32_t>(std::filesystem::file_size(filePath));
    std::string fileNameOnly = std::filesystem::path(filePath).filename().string();

    int attempts = 0;
    const int MAX_ATTEMPTS = 3;

    std::vector<uint8_t> fileNameBuf(fileNameOnly.begin(), fileNameOnly.end());
    fillPadding(fileNameBuf, 255);

    while (attempts < MAX_ATTEMPTS) {
        attempts++;
        std::cout << "Sending file attempt " << attempts << "/" << MAX_ATTEMPTS << "..." << std::endl;

        // בקשה 828: שליחת קובץ מוצפן
        std::vector<uint8_t> packet;

        // Header (23 בתים)
        packet.insert(packet.end(), clientId.begin(), clientId.end());
        packet.push_back(CLIENT_VERSION);
        writeUint16LE(packet, RequestCode::SEND_FILE);

        uint32_t contentSize = static_cast<uint32_t>(encryptedFile.size());
        uint32_t payloadSize = 4 + 4 + 2 + 2 + 255 + contentSize;
        writeUint32LE(packet, payloadSize);

        // Payload
        writeUint32LE(packet, contentSize);
        writeUint32LE(packet, origFileSize);
        writeUint16LE(packet, 1); // Packet Number
        writeUint16LE(packet, 1); // Total Packets

        packet.insert(packet.end(), fileNameBuf.begin(), fileNameBuf.end());
        packet.insert(packet.end(), encryptedFile.begin(), encryptedFile.end());

        if (!network->sendData(packet)) {
            return false;
        }

        // קבלת תשובת ה-CRC מהשרת (Opcode 1603)
        std::vector<uint8_t> responseHeader;
        if (!network->receiveData(responseHeader, 7)) {
            return false;
        }

        uint16_t code = readUint16LE(&responseHeader[1]);
        uint32_t resPayloadSize = readUint32LE(&responseHeader[3]);

        if (code == ResponseCode::FILE_RECEIVED_CRC) {
            std::vector<uint8_t> payload;
            if (!network->receiveData(payload, resPayloadSize)) {
                return false;
            }

            // Payload: Client ID (16) + Content Size (4) + Orig Size (4) + Name (255) + Server CRC (4)
            if (payload.size() >= 16 + 4 + 255 + 4) { // סה"כ 279 בתים בדיוק כמו שהשרת שולח
                uint32_t serverCrc = readUint32LE(&payload[16 + 4 + 255]);
                std::cout << "Local CRC: " << origCrc << ", Server CRC: " << serverCrc << std::endl;

                if (serverCrc == origCrc) {
                    std::cout << "CRC matches! Sending confirmation 900..." << std::endl;
                    // שליחת אישור תקינות 900
                    std::vector<uint8_t> ackPacket;
                    ackPacket.insert(ackPacket.end(), clientId.begin(), clientId.end());
                    ackPacket.push_back(CLIENT_VERSION);
                    writeUint16LE(ackPacket, RequestCode::CRC_VALID);
                    writeUint32LE(ackPacket, 255);
                    ackPacket.insert(ackPacket.end(), fileNameBuf.begin(), fileNameBuf.end());
                    network->sendData(ackPacket);

                    // קריאת כותרת תגובה מהשרת (7 בתים בלבד)
                    std::vector<uint8_t> finalAck;
                    network->receiveData(finalAck, 7);
                    return true;
                }
                else {
                    std::cerr << "CRC Mismatch!" << std::endl;
                    if (attempts < MAX_ATTEMPTS) {
                        // שליחת בקשה לניסיון חוזר 901
                        std::vector<uint8_t> retryPacket;
                        retryPacket.insert(retryPacket.end(), clientId.begin(), clientId.end());
                        retryPacket.push_back(CLIENT_VERSION);
                        writeUint16LE(retryPacket, RequestCode::CRC_INVALID_RETRY);
                        writeUint32LE(retryPacket, 255);
                        retryPacket.insert(retryPacket.end(), fileNameBuf.begin(), fileNameBuf.end());
                        network->sendData(retryPacket);

                        // קריאת כותרת תגובה מהשרת (7 בתים בלבד)
                        std::vector<uint8_t> ackBuf;
                        network->receiveData(ackBuf, 7);
                    }
                }
            }
        }
    } 

    // שליחת ביטול 902 מחוץ ללולאה רק אחרי שכל 3 הניסיונות נכשלו באמת
    std::cout << "Failed CRC verification after 3 attempts. Sending abort 902..." << std::endl;
    std::vector<uint8_t> abortPacket;
    abortPacket.insert(abortPacket.end(), clientId.begin(), clientId.end());
    abortPacket.push_back(CLIENT_VERSION);
    writeUint16LE(abortPacket, RequestCode::CRC_INVALID_ABORT);
    writeUint32LE(abortPacket, 255);

    fileNameBuf.assign(fileNameOnly.begin(), fileNameOnly.end());
    fillPadding(fileNameBuf, 255);
    abortPacket.insert(abortPacket.end(), fileNameBuf.begin(), fileNameBuf.end());
    network->sendData(abortPacket);

    // קריאת כותרת תגובה מהשרת (7 בתים בלבד)
    std::vector<uint8_t> finalAck;
    network->receiveData(finalAck, 7);

    return false;
}
