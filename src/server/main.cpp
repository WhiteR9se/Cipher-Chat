/*
 * CipherChat server entry point
 */

#include "server.hpp"
#include "utils.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

using namespace cipherchat;

namespace {
CipherChatServer* g_server = nullptr;
std::atomic<bool> g_running{true};

void handle_signal(int) {
    g_running = false;
    if (g_server) {
        g_server->stop();
    }
}
} // namespace

int main(int argc, char** argv) {
    std::string bind_addr;
    uint16_t port = 7777;

    if (argc >= 2) {
        port = static_cast<uint16_t>(std::stoi(argv[1]));
    }
    if (argc >= 3) {
        bind_addr = argv[2];
    }

    set_log_level(LogLevel::Info);

    try {
        CipherChatServer server(bind_addr, port);
        g_server = &server;

        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);

        server.start();
        std::cout << "CipherChat server running on " << (bind_addr.empty() ? "0.0.0.0" : bind_addr)
                  << ":" << port << std::endl;

        // Block until termination signal.
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        server.stop();
    } catch (const std::exception& ex) {
        log_error(std::string("Server error: ") + ex.what());
        return 1;
    }

    return 0;
}

