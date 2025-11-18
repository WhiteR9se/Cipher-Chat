/*
 * CipherChat - secure relay server
 */

#pragma once

#include "crypto.hpp"
#include "protocol.hpp"
#include "utils.hpp"

#include <atomic>
#include <memory>
#include <map>
#include <mutex>
#include <deque>
#include <string>
#include <thread>
#include <vector>

namespace cipherchat {

struct ClientContext {
    int socket_fd = -1;
    uint16_t client_id = 0;
    std::string username;
    std::vector<uint8_t> control_key;
    std::thread worker;
    std::atomic<bool> active {false};
    uint16_t current_room = 0;
};

struct RoomState {
    uint16_t room_id = 0;
    std::string name;
    std::vector<uint8_t> room_key;
    std::vector<uint16_t> members;
    std::deque<std::vector<uint8_t>> history_payloads;
};

class CipherChatServer {
public:
    CipherChatServer(std::string bind_address, uint16_t port);
    ~CipherChatServer();

    void start();
    void stop();

private:
    void accept_loop();
    void handle_client(std::shared_ptr<ClientContext> client);
    bool perform_handshake(const std::shared_ptr<ClientContext>& client);
    bool send_control(const std::shared_ptr<ClientContext>& client,
                      const std::map<std::string, std::string>& kv);
    bool process_control_command(const std::shared_ptr<ClientContext>& client,
                                 const std::map<std::string, std::string>& kv);
    void broadcast_room_event(uint16_t room_id,
                              const std::string& event,
                              uint16_t actor_id,
                              const std::string& username);
    void ensure_room_exists(const std::string& room_name);
    std::optional<uint16_t> room_id_by_name(const std::string& name);
    std::string room_name_by_id(uint16_t room_id);
    bool send_room_key(const std::shared_ptr<ClientContext>& client, uint16_t room_id);
    void send_room_roster(const std::shared_ptr<ClientContext>& client, uint16_t room_id);
    void send_room_history(const std::shared_ptr<ClientContext>& client, uint16_t room_id);
    void remove_client_from_room(uint16_t room_id, uint16_t client_id);
    void shutdown_client(const std::shared_ptr<ClientContext>& client);
    void relay_chat_message(const std::shared_ptr<ClientContext>& client,
                            const ChatCipherEnvelope& env,
                            const std::vector<uint8_t>& payload);

    void append_room_history(uint16_t room_id, const std::vector<uint8_t>& payload);

    std::string bind_address_;
    uint16_t port_;
    int listen_fd_ = -1;
    std::atomic<bool> running_ {false};
    std::thread accept_thread_;

    std::mutex clients_mutex_;
    std::map<uint16_t, std::shared_ptr<ClientContext>> clients_;
    uint16_t next_client_id_ = 1;

    std::mutex rooms_mutex_;
    std::map<uint16_t, RoomState> rooms_;
    std::map<std::string, uint16_t> room_name_to_id_;
    uint16_t next_room_id_ = 1;
};

} // namespace cipherchat

