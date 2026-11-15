#include "SetupManager.h" 
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <stdexcept>

// בנאי - מאתחל את המערך
SetupManager::SetupManager() {
    std::memset(identity.clientId, 0, sizeof(identity.clientId));
}

// פונקציית עזר לניקוי שוליים (מנקה רווחים, טאבים, ירידות שורה, מירכאות כפולות ופסיקים)
std::string SetupManager::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n\",");
    if (first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of(" \t\r\n\",");
    return str.substr(first, (last - first + 1));
}

// המרת מחרוזת Hex לבתים
std::vector<uint8_t> SetupManager::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) return bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        catch (const std::exception&) {
            return {};
        }
    }
    return bytes;
}

// המרת בתים למחרוזת Hex
std::string SetupManager::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// פונקציית עזר לבדיקה אם מחרוזת מכילה תת-מחרוזת ללא תלות באותיות קטנות/גדולות
static bool containsIgnoreCase(const std::string& str, const std::string& substr) {
    if (substr.empty()) return true;
    auto it = std::search(
        str.begin(), str.end(),
        substr.begin(), substr.end(),
        [](char c1, char c2) {
            return std::tolower(static_cast<unsigned char>(c1)) ==
                std::tolower(static_cast<unsigned char>(c2));
        }
    );
    return it != str.end();
}

// פונקציית עזר לבדיקת תקינות כתובת IPv4 
static bool isValidIp(const std::string& ip) {
    std::stringstream ss(ip);
    std::string segment;
    int count = 0;

    while (std::getline(ss, segment, '.')) {
        count++;
        if (segment.empty() || segment.length() > 3) return false;
        for (char c : segment) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        try {
            int num = std::stoi(segment);
            if (num < 0 || num > 255) return false;
        }
        catch (const std::exception&) {
            return false;
        }
    }
    return count == 4;
}

// פונקציית עזר לבדיקת תקינות מספר הפורט
static bool isValidPort(uint32_t port) {
    return port >= 1 && port <= 65535;
}

// קריאת קובץ transfer והסריקה לפי הפורמט
bool SetupManager::loadTransferInfo(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {//פתיחת קובץ
        std::cerr << "Error: Cannot open config file: " << filename << std::endl;
        return false;
    }

    std::string line;
    std::string ipStr, portStr, clientStr;
    std::vector<std::string> parsedFiles;
    bool inFilesArray = false; //דגל אם אנחנו כרגע בקריאת נתיבי הקבצים

    while (std::getline(file, line)) {
        //  טיפול בשורות הנמצאות בתוך מערך קבצים  files
        if (inFilesArray) {
            size_t closeBracket = line.find(']');
            if (closeBracket != std::string::npos) {
                inFilesArray = false; // הגענו לסוגר הסוגר
                std::string beforeBracket = line.substr(0, closeBracket);//חילוץ הנתיב האחרון ברשימה
                std::string filePath = trim(beforeBracket);
                if (!filePath.empty()) {
                    parsedFiles.push_back(filePath);//דחיפה כאיבר האחרון בוקטור
                }
                continue;//ממשיכים לשורה הבאה בקובץ
            }
            std::string filePath = trim(line);//לא הגענו לנתיב האחרון-נחלץ את האחד הבא
            if (!filePath.empty()) {
                parsedFiles.push_back(filePath);
            }
            continue;
        }

        //  בדיקה אם מופיע נקודתיים בשורה
        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) {
            continue; // דילוג על שורות ללא נקודתיים (כמו סוגריים מסולסלים)
        }

        //  פיצול לשני חלקים: מפתח (לפני נקודתיים) וערך (אחרי נקודתיים)
        std::string rawKeyPart = line.substr(0, colonPos);
        std::string rawValPart = line.substr(colonPos + 1);

        std::string cleanKeyPart = trim(rawKeyPart);
        std::string cleanValPart = trim(rawValPart);

        // שיוך הערכים לפי המפתח בבדיקה שאינה תלויה באותיות קטנות/גדולות
        if (containsIgnoreCase(cleanKeyPart, "server")) {
            continue; // כותרת אובייקט סרבר
        }
        else if (containsIgnoreCase(cleanKeyPart, "ip")) {
            if (!cleanValPart.empty()) {
                ipStr = cleanValPart;
            }
        }
        else if (containsIgnoreCase(cleanKeyPart, "port")) {
            if (!cleanValPart.empty()) {
                portStr = cleanValPart;
            }
        }
        else if (containsIgnoreCase(cleanKeyPart, "client") || containsIgnoreCase(cleanKeyPart, "name")) {
            if (!cleanValPart.empty()) {
                clientStr = cleanValPart;
            }
        }
        else if (containsIgnoreCase(cleanKeyPart, "files") || containsIgnoreCase(cleanKeyPart, "file")) {
            size_t openBracket = rawValPart.find('[');
            size_t closeBracket = rawValPart.find(']');

            if (openBracket != std::string::npos && closeBracket != std::string::npos) {
                // רשימה בשורה אחת: ["file1.txt", "file2.txt"]
                std::string inner = rawValPart.substr(openBracket + 1, closeBracket - openBracket - 1);
                std::stringstream ss(inner);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    std::string filePath = trim(item);
                    if (!filePath.empty()) {
                        parsedFiles.push_back(filePath);
                    }
                }
            }
            else if (openBracket != std::string::npos) {
                // תחילת רשימה רב-שורתית: "files": [
                inFilesArray = true;
                std::string rest = rawValPart.substr(openBracket + 1);
                std::string filePath = trim(rest);
                if (!filePath.empty()) {
                    parsedFiles.push_back(filePath);
                }
            }
            else if (!cleanValPart.empty()) {
                // נתיב קובץ יחיד ללא סוגריים מרובעים
                parsedFiles.push_back(cleanValPart);
            }
        }
    }
    file.close();

    //   אם הגענו לסוף קובץ ומערך הקבצים לא נסגר עם ']'
    if (inFilesArray) {
        std::cerr << "Error: Unclosed files array in " << filename << " (reached EOF without ']')" << std::endl;
        return false;
    }

    // בדיקות תקינות קפדניות (חובה שיופיעו כל 4 הנתונים: IP, Port, שם לקוח, ולפחות נתיב קובץ אחד)
    if (ipStr.empty() || !isValidIp(ipStr)) {
        std::cerr << "Error: Missing or invalid IPv4 address in " << filename << ": '" << ipStr << "'" << std::endl;
        return false;
    }

    if (portStr.empty()) {
        std::cerr << "Error: Missing port number in " << filename << std::endl;
        return false;
    }

    uint32_t parsedPort = 0;
    try {
        parsedPort = std::stoul(portStr);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: Invalid port number format in " << filename << ": " << portStr << " (" << e.what() << ")" << std::endl;
        return false;
    }

    if (!isValidPort(parsedPort)) {
        std::cerr << "Error: Port out of range (1-65535) in " << filename << ": " << parsedPort << std::endl;
        return false;
    }

    if (clientStr.empty() || clientStr.length() > 100) {
        std::cerr << "Error: Client name must be between 1 and 100 characters in " << filename << ": '" << clientStr << "'" << std::endl;
        return false;
    }

    if (parsedFiles.empty()) {
        std::cerr << "Error: No valid file paths found in " << filename << std::endl;
        return false;
    }

    // שמירת המידע המאומת ב-config
    config.serverIp = ipStr;
    config.serverPort = static_cast<uint16_t>(parsedPort);
    config.clientName = clientStr;
    config.filePaths = parsedFiles;
    config.filePath = parsedFiles[0];

    return true;
}

// בדיקה אם me.info קיים בדיסק
bool SetupManager::existsMeInfo(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

// קריאת me.info לתוך identity
bool SetupManager::loadMeInfo(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        identity.isRegistered = false;
        return false;
    }

    std::string line1, line2, line3;
    if (!std::getline(file, line1) || !std::getline(file, line2)) {
        std::cerr << "Warning: me.info is incomplete." << std::endl;
        file.close();
        identity.isRegistered = false;
        return false;
    }

    identity.clientName = trim(line1);
    identity.clientIdHex = trim(line2);

    if (identity.clientIdHex.length() != 32) {
        std::cerr << "Error: Invalid clientIdHex length in " << filename << " (must be 32 hex characters)" << std::endl;
        file.close();
        identity.isRegistered = false;
        return false;
    }

    std::vector<uint8_t> bytes = hexToBytes(identity.clientIdHex);
    if (bytes.size() != 16) {
        std::cerr << "Error: Failed to parse clientIdHex bytes in " << filename << std::endl;
        file.close();
        identity.isRegistered = false;
        return false;
    }

    std::memcpy(identity.clientId, bytes.data(), 16);

    if (std::getline(file, line3)) {
        identity.privateKey = trim(line3);
    }

    file.close();
    identity.isRegistered = true;
    return true;
}

// שמירת me.info מתוך identity
bool SetupManager::saveMeInfo(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot write to " << filename << std::endl;
        return false;
    }

    file << identity.clientName << "\n";

    if (identity.clientIdHex.empty()) {
        std::vector<uint8_t> bytes(identity.clientId, identity.clientId + 16);
        identity.clientIdHex = bytesToHex(bytes);
    }
    file << identity.clientIdHex << "\n";

    if (!identity.privateKey.empty()) {
        file << identity.privateKey << "\n";
    }

    file.close();
    return true;
}

// שמירת המפתח הפרטי לקובץ priv.key
bool SetupManager::savePrivateKey(const std::string& filename, const std::string& privKey) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot write to " << filename << std::endl;
        return false;
    }
    file << privKey << "\n";
    file.close();
    return true;
}

// טעינת המפתח הפרטי מקובץ priv.key
bool SetupManager::loadPrivateKey(const std::string& filename, std::string& privKeyOut) { 
    std::ifstream file(filename);
        if (!file.is_open()) 
            return false; 
        std::string line; 
        if (std::getline(file, line)) { 
            privKeyOut = trim(line); 
            identity.privateKey = privKeyOut; 
            file.close(); return true; 
        } 
        file.close(); 
        return false; 
} 

bool SetupManager::loadPrivateKey(const std::string& filename) { 
    std::string dummy; 
    return loadPrivateKey(filename, dummy); 
}

// פונקציות גישה 
const TransferInfo& SetupManager::getConfig() const {
    return config;
}

const ClientInfo& SetupManager::getIdentity() const {
    return identity;
}