#include "Network.h" 
#include <iostream>

using boost::asio::ip::tcp;

Network::Network(const std::string& serverIp, uint16_t serverPort)
    : ip(serverIp), port(serverPort), socket(ioContext), connected(false) {
}

Network::~Network() {
    disconnect();
}

bool Network::connect() {
    try {
        if (connected) {
            disconnect();
        }

        tcp::resolver resolver(ioContext);
        auto endpoints = resolver.resolve(ip, std::to_string(port));

        boost::asio::connect(socket, endpoints);
        connected = true;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Network Error (connect): " << e.what() << std::endl;
        connected = false;
        return false;
    }
}

void Network::disconnect() {
    if (connected) {
        boost::system::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
        connected = false;
    }
}

bool Network::isConnected() const {
    return connected;
}

bool Network::sendData(const std::vector<uint8_t>& data) {
    if (!connected || data.empty()) {
        std::cerr << "Network Error: Not connected or data is empty." << std::endl;
        return false;
    }

    try {
        boost::asio::write(socket, boost::asio::buffer(data));
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Network Error (sendData): " << e.what() << std::endl;
        connected = false;
        return false;
    }
}

bool Network::receiveData(std::vector<uint8_t>& buffer, size_t bytesToRead) {
    if (!connected || bytesToRead == 0) {
        std::cerr << "Network Error: Not connected or bytesToRead is 0." << std::endl;
        return false;
    }

    try {
        buffer.resize(bytesToRead);
        boost::asio::read(socket, boost::asio::buffer(buffer.data(), bytesToRead));
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Network Error (receiveData): " << e.what() << std::endl;
        connected = false;
        return false;
    }
}