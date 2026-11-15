#ifndef CRYPTO_MANAGER_H_ 
#define CRYPTO_MANAGER_H_

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

class CryptoHandler {
public:
    CryptoHandler() = default;
    static bool generateRsaKeyPair(std::string& privateKeyBase64, std::vector<uint8_t>& publicKeyBytes);//יצירת זוג מפתחות אסימטריים ציבורי ופרטי
    static bool decryptAesKey(const std::string& privateKeyBase64, const std::vector<uint8_t>& encryptedAesKey, std::vector<uint8_t>& aesKey);// באמצעות המפתח הפרטי מפענחים את המפתח הסימטרי המוצפן שהתקבל מהשרת 
    static bool encryptFileAes(const std::vector<uint8_t>& aesKey, const std::string& inputFilePath, std::vector<uint8_t>& encryptedOutput);//הצפנת קובץ 
    static unsigned long memcrc(const char* b, size_t n);
    static bool calculateCrc(const std::string& inputFilePath, uint32_t& crcResult);//חישוב CRC עבור קובץ
    static std::string base64Encode(const std::vector<uint8_t>& data);//קידוד ממערך בתים בינאריים למחרוזת קריאה
    static std::vector<uint8_t> base64Decode(const std::string& encodedStr);//פענוח ממחרוזת למערך בתים בינארי
};

#endif /* CRYPTO_HANDLER_H_ */

