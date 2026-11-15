#ifndef CLIENT_CONTROLLER_H_ 
#define CLIENT_CONTROLLER_H_ 

#include "SetupManager.h" 
#include "CryptoHandler.h" 
#include "Network.h" 
#include "Protocol.h" 

#include <string>
#include <vector>
#include <cstdint>

class ClientController {
private:
    SetupManager setupManager;
    Network* network;

    // נתוני לקוח
    std::string clientName;
    std::string filePath;
    std::string serverIp;
    uint16_t serverPort;

    std::vector<uint8_t> clientId;
    std::string privateKeyBase64;
    std::vector<uint8_t> aesKey;

    // שלבי הפרוטוקול
    bool handleRegistration();
    bool handleReconnection();
    bool sendPublicKey();
    bool sendEncryptedFile();

    // פונקציות עזר לבניית פקטות
    void fillPadding(std::vector<uint8_t>& vec, size_t targetSize);

public:
    ClientController();
    ~ClientController();

    // הפעלת התהליך כולו
    bool start();
};

#endif /* CLIENT_CONTROLLER_H_ */
