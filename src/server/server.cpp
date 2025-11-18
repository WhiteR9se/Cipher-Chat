/*
 * CipherChat - relay server implementation
 */

#include "server.hpp"

#include "crypto.hpp"
#include "protocol.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <chrono>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <iomanip>
#include <stdexcept>

namespace cipherchat {

namespace {
constexpr const char* kDefaultRoomName = "lobby";
constexpr std::size_t kMaxRoomHistory = 100;

FileLogger g_server_file_logger("logs/server.log");

std::string level_to_short(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:
            return "DEBUG";
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warn:
            return "WARN";
        case LogLevel::Error:
            return "ERROR";
        default:
            return "LOG";
    }
}

void server_log(LogLevel level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now{};
#if defined(_WIN32)
    localtime_s(&tm_now, &tt);
#else
    localtime_r(&tt, &tm_now);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_now);

    log(level, message);
    std::string prefix = "[" + level_to_short(level) + " " + buffer + "] ";
    try {
        g_server_file_logger.write(prefix + message);
    } catch (const std::exception&) {
        // Fall back silently if file logging fails.
    }
}

inline void server_log_info(const std::string& message) {
    server_log(LogLevel::Info, message);
}

inline void server_log_warn(const std::string& message) {
    server_log(LogLevel::Warn, message);
}

inline void server_log_error(const std::string& message) {
    server_log(LogLevel::Error, message);
}

std::vector<uint8_t> control_aad(uint16_t client_id) {
    std::vector<uint8_t> aad = {'C', 'T', 'R', 'L'};
    aad.push_back(static_cast<uint8_t>(client_id >> 8));
    aad.push_back(static_cast<uint8_t>(client_id & 0xFF));
    return aad;
}

std::vector<uint8_t> chat_aad(uint16_t room_id, uint16_t sender_id) {
    std::vector<uint8_t> aad = {'C', 'H', 'A', 'T'};
    aad.push_back(static_cast<uint8_t>(room_id >> 8));
    aad.push_back(static_cast<uint8_t>(room_id & 0xFF));
    aad.push_back(static_cast<uint8_t>(sender_id >> 8));
    aad.push_back(static_cast<uint8_t>(sender_id & 0xFF));
    return aad;
}
std::string summarize_hex(const std::vector<uint8_t>& data) {
    auto hex = hex_encode(data);
    if (hex.size() > 96) {
        return hex.substr(0, 96) + "...";
    }
    return hex;
}
} // namespace

CipherChatServer::CipherChatServer(std::string bind_address, uint16_t port)
    : bind_address_(std::move(bind_address)), port_(port) {}

CipherChatServer::~CipherChatServer() {
    stop();
}

void CipherChatServer::start() {
    if (running_) {
        return;
    }

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        throw std::runtime_error("Failed to create socket: " + std::string(std::strerror(errno)));
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (bind_address_.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        addr.sin_addr.s_addr = inet_addr(bind_address_.c_str());
    }

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        throw std::runtime_error("Failed to bind: " + std::string(std::strerror(errno)));
    }

    if (::listen(listen_fd_, 16) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        throw std::runtime_error("Failed to listen: " + std::string(std::strerror(errno)));
    }

    std::error_code ec;
    std::filesystem::create_directories("logs", ec);
    if (ec) {
        server_log_warn("Failed to create logs directory: " + ec.message());
    }
    {
        std::ofstream server_log_stream("logs/server.log", std::ios::app);
        server_log_stream << "\n\n";
    }

    server_log_info("CipherChat server listening on port " + std::to_string(port_));
    running_ = true;

    ensure_room_exists(kDefaultRoomName);

    accept_thread_ = std::thread(&CipherChatServer::accept_loop, this);
}

void CipherChatServer::stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    std::vector<std::shared_ptr<ClientContext>> to_join;
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto& [id, client] : clients_) {
            to_join.push_back(client);
        }
        clients_.clear();
    }

    for (auto& client : to_join) {
        if (!client) {
            continue;
        }
        if (client->socket_fd >= 0) {
            ::shutdown(client->socket_fd, SHUT_RDWR);
            ::close(client->socket_fd);
            client->socket_fd = -1;
        }
        if (client->worker.joinable()) {
            client->worker.join();
        }
    }

    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        rooms_.clear();
        room_name_to_id_.clear();
        next_room_id_ = 1;
    }
    next_client_id_ = 1;

    std::error_code ec_logs;
    std::filesystem::path logs_path{"logs"};
    if (std::filesystem::exists(logs_path, ec_logs)) {
        for (const auto& entry : std::filesystem::directory_iterator(logs_path, ec_logs)) {
            if (ec_logs) {
                break;
            }
            if (!entry.is_regular_file()) {
                continue;
            }
            auto filename = entry.path().filename().string();
            if (filename.rfind("room_", 0) == 0) {
                std::filesystem::remove(entry.path(), ec_logs);
                if (ec_logs) {
                    server_log_warn("Failed to remove room log " + entry.path().string() + ": " + ec_logs.message());
                    ec_logs.clear();
                }
            }
        }
    }
    std::error_code ec_history;
    std::filesystem::remove_all("history", ec_history);
}

void CipherChatServer::accept_loop() {
    while (running_) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!running_) {
                break;
            }
            server_log_warn("Accept failed: " + std::string(std::strerror(errno)));
            continue;
        }

        auto client = std::make_shared<ClientContext>();
        client->socket_fd = client_fd;
        client->active = true;

        client->worker = std::thread(&CipherChatServer::handle_client, this, client);
    }
}

void CipherChatServer::handle_client(std::shared_ptr<ClientContext> client) {
    server_log_info("Client connected fd=" + std::to_string(client->socket_fd));
    try {
        if (!perform_handshake(client)) {
            server_log_warn("Handshake failed, terminating client fd=" + std::to_string(client->socket_fd));
            shutdown_client(client);
            return;
        }
    } catch (const std::exception& ex) {
        server_log_error(std::string("Handshake exception: ") + ex.what());
        shutdown_client(client);
        return;
    }

    while (client->active) {
        auto frame_opt = receive_frame(client->socket_fd);
        if (!frame_opt.has_value()) {
            break;
        }
        const Frame& frame = frame_opt.value();

        if (frame.kind == MessageKind::Control) {
            std::vector<uint8_t> nonce;
            std::vector<uint8_t> ciphertext;
            std::vector<uint8_t> tag;
            if (!unpack_control_payload(frame.payload, nonce, ciphertext, tag)) {
                server_log_warn("Invalid control payload");
                continue;
            }
            Ciphertext wrapped{nonce, ciphertext, tag};
            try {
                auto aad = control_aad(client->client_id);
                auto plaintext = aes256_gcm_decrypt(client->control_key, wrapped, aad);
                std::string message(plaintext.begin(), plaintext.end());
                auto kv = parse_kv_string(message);
                if (!process_control_command(client, kv)) {
                    server_log_warn("Failed to process control command");
                }
            } catch (const std::exception& ex) {
                server_log_error(std::string("Control decrypt failed: ") + ex.what());
            }
        } else if (frame.kind == MessageKind::ChatCipher) {
            auto env_opt = unpack_chat_envelope(frame.payload);
            if (!env_opt.has_value()) {
                server_log_warn("Failed to unpack chat envelope");
                continue;
            }
            auto env = env_opt.value();
            relay_chat_message(client, env, frame.payload);
        } else {
            server_log_warn("Unknown frame kind received");
        }
    }

    shutdown_client(client);
}

bool CipherChatServer::perform_handshake(const std::shared_ptr<ClientContext>& client) {
    KeyPair server_keys = generate_x25519_keypair();
    std::map<std::string, std::string> kv;
    kv["type"] = "server_hello";
    kv["pub"] = base64_encode(server_keys.public_key);

    Frame hello_frame;
    hello_frame.kind = MessageKind::Handshake;
    std::string hello_payload = kv_string(kv);
    hello_frame.payload.assign(hello_payload.begin(), hello_payload.end());

    if (!send_frame(client->socket_fd, hello_frame)) {
        return false;
    }

    auto frame_opt = receive_frame(client->socket_fd);
    if (!frame_opt.has_value()) {
        return false;
    }
    Frame frame = frame_opt.value();
    if (frame.kind != MessageKind::Handshake) {
        return false;
    }

    std::string client_msg(frame.payload.begin(), frame.payload.end());
    auto params = parse_kv_string(client_msg);
    if (params["type"] != "client_hello") {
        return false;
    }
    const auto pub_b64 = params["pub"];
    const auto username = params["name"];
    auto pub_bytes_opt = base64_decode(pub_b64);
    if (!pub_bytes_opt.has_value()) {
        return false;
    }
    auto client_pub = pub_bytes_opt.value();
    auto shared_secret = compute_x25519_shared(server_keys.private_key, client_pub);
    auto control_key = hkdf_sha256(shared_secret, "cipherchat-control", 32);

    uint16_t client_id = 0;
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        client_id = next_client_id_++;
        client->client_id = client_id;
        client->username = username.empty() ? ("guest" + std::to_string(client_id)) : username;
        client->control_key = control_key;
        clients_[client_id] = client;
    }

    ensure_room_exists(kDefaultRoomName);
    auto lobby_id = room_id_by_name(kDefaultRoomName).value();

    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto& lobby = rooms_[lobby_id];
        if (std::find(lobby.members.begin(), lobby.members.end(), client_id) == lobby.members.end()) {
            lobby.members.push_back(client_id);
        }
    }

    client->current_room = lobby_id;

    std::map<std::string, std::string> welcome_plain{
        {"type", "handshake_ack"},
        {"id", std::to_string(client_id)},
        {"room", kDefaultRoomName}
    };
    Frame ack_frame;
    ack_frame.kind = MessageKind::Handshake;
    std::string ack_payload = kv_string(welcome_plain);
    ack_frame.payload.assign(ack_payload.begin(), ack_payload.end());
    send_frame(client->socket_fd, ack_frame);

    send_room_key(client, lobby_id);
    send_room_roster(client, lobby_id);
    send_room_history(client, lobby_id);

    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        std::vector<std::string> room_names;
        for (const auto& [id, room] : rooms_) {
            room_names.push_back(room.name);
        }
        std::string joined;
        for (std::size_t i = 0; i < room_names.size(); ++i) {
            if (i > 0) {
                joined += ',';
            }
            joined += room_names[i];
        }
        send_control(client, {{"type", "room_list"}, {"rooms", joined}});
    }

    broadcast_room_event(lobby_id, "join", client->client_id, client->username);
    server_log_info("Client #" + std::to_string(client_id) + " authenticated as " + client->username);
    return true;
}

bool CipherChatServer::send_control(const std::shared_ptr<ClientContext>& client,
                                    const std::map<std::string, std::string>& kv) {
    if (!client || client->socket_fd < 0 || client->control_key.empty()) {
        return false;
    }
    std::string payload_str = kv_string(kv);
    std::vector<uint8_t> plaintext(payload_str.begin(), payload_str.end());
    auto aad = control_aad(client->client_id);
    auto wrapped = aes256_gcm_encrypt(client->control_key, plaintext, aad);
    auto packed = pack_control_payload(wrapped.nonce, wrapped.data, wrapped.tag);
    Frame frame{MessageKind::Control, std::move(packed)};
    return send_frame(client->socket_fd, frame);
}

bool CipherChatServer::process_control_command(const std::shared_ptr<ClientContext>& client,
                                               const std::map<std::string, std::string>& kv) {
    auto type_it = kv.find("type");
    if (type_it == kv.end()) {
        return false;
    }
    const std::string& type = type_it->second;

    if (type == "join") {
        auto room_it = kv.find("room");
        if (room_it == kv.end()) {
            return false;
        }
        std::string room_name = room_it->second;
        ensure_room_exists(room_name);
        auto room_id_opt = room_id_by_name(room_name);
        if (!room_id_opt.has_value()) {
            return false;
        }
        auto room_id = room_id_opt.value();

        if (client->current_room == room_id) {
            send_control(client, {{"type", "info"}, {"message", "Already in " + room_name}});
            return true;
        }

        uint16_t previous_room = client->current_room;
        if (client->current_room != 0) {
            remove_client_from_room(client->current_room, client->client_id);
            broadcast_room_event(previous_room, "leave", client->client_id, client->username);
        }

        {
            std::lock_guard<std::mutex> lock(rooms_mutex_);
            auto& room = rooms_[room_id];
            if (std::find(room.members.begin(), room.members.end(), client->client_id) == room.members.end()) {
                room.members.push_back(client->client_id);
            }
        }

        client->current_room = room_id;
        send_room_key(client, room_id);
        send_room_roster(client, room_id);
        send_room_history(client, room_id);
        send_control(client, {{"type", "join_ok"}, {"room", room_name}, {"id", std::to_string(room_id)}});
        broadcast_room_event(room_id, "join", client->client_id, client->username);
        return true;
    }

    if (type == "join_id") {
        auto id_it = kv.find("id");
        if (id_it == kv.end()) {
            return false;
        }
        uint16_t room_id = static_cast<uint16_t>(std::stoi(id_it->second));
        std::string room_name = room_name_by_id(room_id);
        if (room_name.empty()) {
            send_control(client, {{"type", "error"}, {"message", "Room id not found"}});
            return true;
        }
        if (client->current_room == room_id) {
            send_control(client, {{"type", "info"}, {"message", "Already in room #" + std::to_string(room_id)}});
            return true;
        }
        uint16_t previous_room = client->current_room;
        if (client->current_room != 0) {
            remove_client_from_room(client->current_room, client->client_id);
            broadcast_room_event(previous_room, "leave", client->client_id, client->username);
        }
        {
            std::lock_guard<std::mutex> lock(rooms_mutex_);
            auto& room = rooms_[room_id];
            if (std::find(room.members.begin(), room.members.end(), client->client_id) == room.members.end()) {
                room.members.push_back(client->client_id);
            }
        }
        client->current_room = room_id;
        send_room_key(client, room_id);
        send_room_roster(client, room_id);
        send_room_history(client, room_id);
        send_control(client, {{"type", "join_ok"}, {"room", room_name}, {"id", std::to_string(room_id)}});
        broadcast_room_event(room_id, "join", client->client_id, client->username);
        return true;
    }

    if (type == "list") {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        std::string joined;
        bool first = true;
        for (const auto& [id, room] : rooms_) {
            if (!first) {
                joined += ',';
            }
            first = false;
            joined += std::to_string(id) + ":" + room.name;
        }
        send_control(client, {{"type", "room_list"}, {"rooms", joined}});
        return true;
    }

    if (type == "leave") {
        if (client->current_room == 0) {
            return true;
        }
        auto room_name = room_name_by_id(client->current_room);
        remove_client_from_room(client->current_room, client->client_id);
        broadcast_room_event(client->current_room, "leave", client->client_id, client->username);
        client->current_room = 0;
        send_control(client, {{"type", "info"}, {"message", "Left " + room_name}});
        return true;
    }

    if (type == "rename") {
        auto name_it = kv.find("name");
        if (name_it == kv.end()) {
            return false;
        }
        std::string old_name = client->username;
        client->username = name_it->second;
        if (client->current_room != 0) {
            broadcast_room_event(client->current_room, "rename", client->client_id, old_name + "->" + client->username);
        }
        send_control(client, {{"type", "info"}, {"message", "Renamed to " + client->username}});
        return true;
    }

    if (type == "rooms_create") {
        auto name_it = kv.find("room");
        if (name_it == kv.end()) {
            return false;
        }
        std::string room_name = name_it->second;
        ensure_room_exists(room_name);
        auto id_opt = room_id_by_name(room_name);
        std::string message = "Room ready: " + room_name;
        if (id_opt.has_value()) {
            message += " (#" + std::to_string(id_opt.value()) + ")";
        }
        send_control(client, {{"type", "info"}, {"message", message}});
        return true;
    }

    return false;
}

void CipherChatServer::broadcast_room_event(uint16_t room_id,
                                            const std::string& event,
                                            uint16_t actor_id,
                                            const std::string& username) {
    std::vector<uint16_t> member_ids;
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(room_id);
        if (it == rooms_.end()) {
            return;
        }
        member_ids = it->second.members;
    }

    for (uint16_t member_id : member_ids) {
        std::shared_ptr<ClientContext> target;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            auto it = clients_.find(member_id);
            if (it == clients_.end()) {
                continue;
            }
            target = it->second;
        }
        if (!target) {
            continue;
        }
        send_control(target, {
            {"type", "peer_event"},
            {"event", event},
            {"user", username},
            {"room", room_name_by_id(room_id)},
            {"id", std::to_string(actor_id)}
        });
    }
}

void CipherChatServer::ensure_room_exists(const std::string& room_name) {
    std::lock_guard<std::mutex> lock(rooms_mutex_);
    auto it = room_name_to_id_.find(room_name);
    if (it != room_name_to_id_.end()) {
        return;
    }

    RoomState room;
    room.room_id = next_room_id_++;
    room.name = room_name;
    room.room_key = random_bytes(32);
    room_name_to_id_[room_name] = room.room_id;
    rooms_[room.room_id] = room;
    server_log_info("Created room " + room_name + " (#" + std::to_string(room.room_id) + ")");
}

std::optional<uint16_t> CipherChatServer::room_id_by_name(const std::string& name) {
    std::lock_guard<std::mutex> lock(rooms_mutex_);
    auto it = room_name_to_id_.find(name);
    if (it == room_name_to_id_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::string CipherChatServer::room_name_by_id(uint16_t room_id) {
    std::lock_guard<std::mutex> lock(rooms_mutex_);
    auto it = rooms_.find(room_id);
    if (it == rooms_.end()) {
        return {};
    }
    return it->second.name;
}

bool CipherChatServer::send_room_key(const std::shared_ptr<ClientContext>& client, uint16_t room_id) {
    RoomState room;
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(room_id);
        if (it == rooms_.end()) {
            return false;
        }
        room = it->second;
    }
    auto key_b64 = base64_encode(room.room_key);
    return send_control(client, {
        {"type", "room_key"},
        {"room", room.name},
        {"key", key_b64},
        {"id", std::to_string(room.room_id)}
    });
}

void CipherChatServer::send_room_roster(const std::shared_ptr<ClientContext>& client, uint16_t room_id) {
    if (!client) {
        return;
    }
    std::string room_name;
    std::vector<std::pair<uint16_t, std::string>> members;
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(room_id);
        if (it == rooms_.end()) {
            return;
        }
        room_name = it->second.name;
        for (uint16_t member_id : it->second.members) {
            std::string name;
            {
                std::lock_guard<std::mutex> lock_clients(clients_mutex_);
                auto client_it = clients_.find(member_id);
                if (client_it != clients_.end()) {
                    name = client_it->second->username;
                }
            }
            if (!name.empty()) {
                members.emplace_back(member_id, name);
            }
        }
    }
    std::string encoded;
    for (std::size_t i = 0; i < members.size(); ++i) {
        if (i > 0) {
            encoded += ',';
        }
        encoded += std::to_string(members[i].first) + ":" + members[i].second;
    }
    send_control(client, {
        {"type", "peer_list"},
        {"room", room_name},
        {"id", std::to_string(room_id)},
        {"members", encoded}
    });
}

void CipherChatServer::send_room_history(const std::shared_ptr<ClientContext>& client, uint16_t room_id) {
    if (!client) {
        return;
    }
    std::deque<std::vector<uint8_t>> history_copy;
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(room_id);
        if (it == rooms_.end()) {
            return;
        }
        history_copy = it->second.history_payloads;
    }

    for (const auto& payload : history_copy) {
        Frame frame{MessageKind::ChatCipher, payload};
        send_frame(client->socket_fd, frame);
    }
    server_log_info("Replayed " + std::to_string(history_copy.size()) + " messages to client #" +
                    std::to_string(client->client_id) + " for room #" + std::to_string(room_id));
}

void CipherChatServer::remove_client_from_room(uint16_t room_id, uint16_t client_id) {
    std::string room_name;
    bool destroy_room = false;
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(room_id);
        if (it == rooms_.end()) {
            return;
        }
        auto& members = it->second.members;
        members.erase(std::remove(members.begin(), members.end(), client_id), members.end());
        room_name = it->second.name;
        if (members.empty() && it->second.name != kDefaultRoomName) {
            destroy_room = true;
            rooms_.erase(it);
            room_name_to_id_.erase(room_name);
        }
    }

    if (destroy_room) {
        server_log_info("Destroyed room " + room_name + " (#" + std::to_string(room_id) + ")");
        std::error_code ec;
        std::filesystem::remove("logs/room_" + std::to_string(room_id) + ".log", ec);
        if (ec) {
            server_log_warn("Failed to remove room log for room #" + std::to_string(room_id) + ": " + ec.message());
        }
    }
}

void CipherChatServer::shutdown_client(const std::shared_ptr<ClientContext>& client) {
    if (!client) {
        return;
    }
    client->active = false;
    if (client->socket_fd >= 0) {
        ::shutdown(client->socket_fd, SHUT_RDWR);
        ::close(client->socket_fd);
        client->socket_fd = -1;
    }

    if (client->current_room != 0) {
        broadcast_room_event(client->current_room, "leave", client->client_id, client->username);
        remove_client_from_room(client->current_room, client->client_id);
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.erase(client->client_id);
    }

    if (client->worker.joinable()) {
        if (client->worker.get_id() == std::this_thread::get_id()) {
            client->worker.detach();
        } else {
            client->worker.join();
        }
    }

    server_log_info("Client #" + std::to_string(client->client_id) + " disconnected");
}

void CipherChatServer::relay_chat_message(const std::shared_ptr<ClientContext>& client,
                                          const ChatCipherEnvelope& env,
                                          const std::vector<uint8_t>& payload) {
    if (env.sender_id != client->client_id) {
        server_log_warn("Sender id mismatch, dropping chat message");
        return;
    }
    if (client->current_room != env.room_id) {
        server_log_warn("Sender room mismatch, dropping chat message");
        return;
    }

    std::vector<uint16_t> target_ids;
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(env.room_id);
        if (it == rooms_.end()) {
            server_log_warn("Unknown room id for chat message");
            return;
        }
        if (std::find(it->second.members.begin(), it->second.members.end(), client->client_id) ==
            it->second.members.end()) {
            server_log_warn("Client not in room, dropping message");
            return;
        }
        target_ids = it->second.members;
    }

    append_room_history(env.room_id, payload);
    for (uint16_t target_id : target_ids) {
        std::shared_ptr<ClientContext> target;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            auto it = clients_.find(target_id);
            if (it == clients_.end()) {
                continue;
            }
            target = it->second;
        }
        if (!target || !target->active || target->socket_fd < 0) {
            continue;
        }

        Frame frame{MessageKind::ChatCipher, payload};
        if (!send_frame(target->socket_fd, frame)) {
            server_log_warn("Failed to relay message to client #" + std::to_string(target_id));
        }
    }

    server_log_info("Relayed ciphertext room #" + std::to_string(env.room_id) +
                    " from client #" + std::to_string(env.sender_id) +
                    " bytes=" + std::to_string(payload.size()) +
                    " data=" + summarize_hex(payload));
}

void CipherChatServer::append_room_history(uint16_t room_id, const std::vector<uint8_t>& payload) {
    {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        auto it = rooms_.find(room_id);
        if (it == rooms_.end()) {
            return;
        }
        it->second.history_payloads.push_back(payload);
        while (it->second.history_payloads.size() > kMaxRoomHistory) {
            it->second.history_payloads.pop_front();
        }
    }

    std::error_code ec;
    std::filesystem::create_directories("logs", ec);
    std::ofstream out("logs/room_" + std::to_string(room_id) + ".log", std::ios::app);
    if (!out) {
        server_log_warn("Unable to write room log for room #" + std::to_string(room_id));
        return;
    }
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now{};
#if defined(_WIN32)
    localtime_s(&tm_now, &tt);
#else
    localtime_r(&tt, &tm_now);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_now);

    out << buffer << "|" << base64_encode(payload) << '\n';
}

} // namespace cipherchat

