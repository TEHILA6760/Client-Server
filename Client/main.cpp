#include "ClientController.h" 
#include <iostream>

int main() {
    try {
        ClientController controller;
        if (controller.start()) {
            std::cout << "Client process completed successfully!\n" << std::endl;
            return 0;
        }
        else {
            std::cerr << "Client process failed.\n" << std::endl;
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal Exception in main: " << e.what() << std::endl;
        return 1;
    }
}
