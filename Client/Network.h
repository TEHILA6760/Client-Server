#ifndef NETWORK_H_ 
#define NETWORK_H_ 

#include<string>
#include <vector>
#include <cstdint>
#include <boost/asio.hpp>

class Network {
private:
    std::string ip;
    uint16_t port;
    boost::asio::io_context ioContext;
    boost::asio::ip::tcp::socket socket;
    bool connected;

public:
    Network(const std::string& serverIp, uint16_t serverPort);
    ~Network();

    // התחברות לשרת ה-TCP
    bool connect();

    // סגירת החיבור באופן מסודר
    void disconnect();

    // בדיקת סטטוס חיבור
    bool isConnected() const;

    // שליחת נתונים בינאריים
    bool sendData(const std::vector<uint8_t>& data);

    // קבלת כמות בתים מוגדרת מהשרת
    bool receiveData(std::vector<uint8_t>& buffer, size_t bytesToRead);
};

#endif /* NETWORK_H_ */
