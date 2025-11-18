/*
 * CipherChat - client
 */

#pragma once

#include "crypto.hpp"
#include "protocol.hpp"

#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace cipherchat {

struct RoomKey {
    uint16_t id = 0;
    std::string name;
    std::vector<uint8_t> key;
};

class CipherChatClient {
public:
    CipherChatClient();
    ~CipherChatClient();

    bool connect_to_server(const std::string& host,
                           uint16_t port,
                           const std::string& username);

    void run();

private:
    bool perform_handshake();
    bool send_control(const std::map<std::string, std::string>& kv);
    void reader_loop();
    void handle_control_payload(const std::vector<uint8_t>& payload);
    void handle_chat_payload(const std::vector<uint8_t>& payload);
    void process_user_input(const std::string& line);
    std::optional<RoomKey> room_by_name(const std::string& name);
    std::optional<RoomKey> room_by_id(uint16_t id);
    void update_room_key(const std::string& name,
                         uint16_t id,
                         const std::vector<uint8_t>& key);
    void show_prompt();

    std::string host_;
    uint16_t port_ = 0;
    std::string username_;

    int socket_fd_ = -1;
    uint16_t client_id_ = 0;
    std::vector<uint8_t> control_key_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::thread reader_thread_;
    std::mutex room_mutex_;
    std::map<uint16_t, RoomKey> rooms_;
    uint16_t current_room_id_ = 0;
    KeyPair client_keys_;
    std::vector<uint8_t> server_public_;

    std::mutex io_mutex_;
    std::map<uint16_t, std::string> peer_names_;
    std::mutex peer_mutex_;
};

} // namespace cipherchat

