/*
 * CipherChat client entry point
 */

#include "client.hpp"
#include "utils.hpp"

#include <iostream>

using namespace cipherchat;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: client <server-host> <port> [username]\n";
        return 1;
    }

    std::string host = argv[1];
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string username = (argc >= 4) ? argv[3] : "guest";

    CipherChatClient client;
    if (!client.connect_to_server(host, port, username)) {
        std::cerr << "Could not connect to server.\n";
        return 1;
    }

    std::cout << "Connected to " << host << ":" << port << " as " << username << std::endl;
    std::cout << "Type /help for commands.\n";
    client.run();
    return 0;
}

