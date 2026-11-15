#include "CryptoHandler.h"
#include "CrcTable.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <filesystem>

// Crypto++ Includes
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/queue.h>


#define UNSIGNED(n) (n & 0xffffffff)//מהקוד מאתר הקורס

// יצירת זוג מפתחות RSA באורך 1024 ביט
bool CryptoHandler::generateRsaKeyPair(std::string& privateKeyBase64, std::vector<uint8_t>& publicKeyBytes) {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // יצירת מפתח פרטי RSA באורך 1024 ביט
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 1024);

        // הפקת המפתח הציבורי במבנה X.509
        CryptoPP::RSA::PublicKey publicKey(privateKey);

        // קידוד המפתח הפרטי ל-Base64
                // קידוד המפתח הפרטי
        std::string privKeyStr;
        CryptoPP::StringSink privSink(privKeyStr);
        privateKey.Save(privSink);

        std::vector<uint8_t> privKeyBytes(privKeyStr.begin(), privKeyStr.end());
        privateKeyBase64 = base64Encode(privKeyBytes);
        privateKey.Save(privSink);
        privateKeyBase64 = base64Encode(privKeyBytes);

        // שמירת המפתח הציבורי במבנה בינארי X.509 (בגודל 160 בתים)
        std::string pubKeyStr;
        CryptoPP::StringSink pubSink(pubKeyStr);
        publicKey.Save(pubSink);

        // העברת הנתונים בצורה בטוחה לוקטור המקורי
        publicKeyBytes.assign(pubKeyStr.begin(), pubKeyStr.end());


        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "CryptoHandler Error (generateRsaKeyPair): " << e.what() << std::endl;
        return false;
    }
}

//  פענוח מפתח ה-AES המוצפן שהתקבל מהשרת באמצעות המפתח הפרטי
bool CryptoHandler::decryptAesKey(const std::string& privateKeyBase64, const std::vector<uint8_t>& encryptedAesKey, std::vector<uint8_t>& aesKey) {
    try {
        if (privateKeyBase64.empty() || encryptedAesKey.empty()) {
            std::cerr << "Error: Private key or encrypted AES key is empty." << std::endl;
            return false;
        }

        // פענוח המפתח הפרטי מ-Base64
        std::vector<uint8_t> privKeyBytes = base64Decode(privateKeyBase64);
        std::string privKeyStr(privKeyBytes.begin(), privKeyBytes.end());

        CryptoPP::StringSource privSource(privKeyStr, true);
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.Load(privSource);

        // יצירת מפענח RSA
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        // העברת המפתח המוצפן למחרוזת לצורך הפענוח
        std::string encryptedAesStr(encryptedAesKey.begin(), encryptedAesKey.end());
        std::string decryptedAesStr;

        CryptoPP::StringSource(encryptedAesStr, true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                new CryptoPP::StringSink(decryptedAesStr)
            )
        );

        aesKey.assign(decryptedAesStr.begin(), decryptedAesStr.end());
        return !aesKey.empty();
    }
    catch (const std::exception& e) {
        std::cerr << "CryptoHandler Error (decryptAesKey): " << e.what() << std::endl;
        return false;
    }
}

//  הצפנת קובץ באמצעות AES-CBC עם IV מאופס (16 בתים של 0)
bool CryptoHandler::encryptFileAes(const std::vector<uint8_t>& aesKey, const std::string& inputFilePath, std::vector<uint8_t>& encryptedOutput) {
    try {
        if (aesKey.empty()) {
            std::cerr << "Error: AES key is empty." << std::endl;
            return false;
        }

        std::ifstream file(inputFilePath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open file for encryption: " << inputFilePath << std::endl;
            return false;
        }

        std::string fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        uint8_t iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(aesKey.data(), aesKey.size(), iv);

        std::string encryptedStr;
        CryptoPP::StringSource(fileData, true,
            new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::StringSink(encryptedStr)
            )
        );

        encryptedOutput.assign(encryptedStr.begin(), encryptedStr.end());
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "CryptoHandler Error (encryptFileAes): " << e.what() << std::endl;
        return false;
    }
}

// 4. פונקציית memcrc הרשמית מאתר הקורס
unsigned long CryptoHandler::memcrc(const char* b, size_t n) {
    unsigned int c = 0;
    unsigned long s = 0;
    unsigned int tabidx;

    for (size_t i = 0; i < n; i++) {
        tabidx = (s >> 24) ^ static_cast<unsigned char>(b[i]);
        s = UNSIGNED((s << 8)) ^ crctab[0][tabidx]; // שימוש בשכבה הראשונה של הטבלה התלת-מימדית שלך
    }

    size_t temp_n = n;
    while (temp_n) {
        c = static_cast<unsigned int>(temp_n & 0377);
        temp_n = temp_n >> 8;
        s = UNSIGNED(s << 8) ^ crctab[0][(s >> 24) ^ c];
    }
    return static_cast<unsigned long>(UNSIGNED(~s));
}


//  calculateCrc - קריאת קובץ והפעלת memcrc (בשיטת RAII ללא new/delete ידני)
bool CryptoHandler::calculateCrc(const std::string& inputFilePath, uint32_t& crcResult) {
    if (!std::filesystem::exists(inputFilePath)) {
        std::cerr << "Cannot open input file " << inputFilePath << std::endl;
        return false;
    }

    std::filesystem::path fpath = inputFilePath;
    std::ifstream f1(inputFilePath, std::ios::binary);
    if (!f1.is_open()) {
        std::cerr << "Cannot open input file " << inputFilePath << std::endl;
        return false;
    }

    size_t size = std::filesystem::file_size(fpath);
    if (size == 0) {
        char emptyBuf = 0;
        crcResult = static_cast<uint32_t>(memcrc(&emptyBuf, 0));
        return true;
    }

    std::vector<char> buffer(size);
    f1.seekg(0, std::ios::beg);
    f1.read(buffer.data(), size);
    f1.close();

    crcResult = static_cast<uint32_t>(memcrc(buffer.data(), size));
    return true;
}

//  קידוד Base64
std::string CryptoHandler::base64Encode(const std::vector<uint8_t>& data) {
    std::string encoded;
    std::string dataStr(data.begin(), data.end());
    CryptoPP::StringSource source(dataStr, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded), false
        )
    );
    return encoded;
}

std::vector<uint8_t> CryptoHandler::base64Decode(const std::string& encodedStr) {
    std::string decodedStr;
    CryptoPP::StringSource source(encodedStr, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decodedStr)
        )
    );
    return std::vector<uint8_t>(decodedStr.begin(), decodedStr.end());
}
