/*
 * CipherChat - client implementation
 */

#include "client.hpp"

#include "protocol.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>

namespace cipherchat {

namespace {
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;

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
} // namespace

CipherChatClient::CipherChatClient() = default;

CipherChatClient::~CipherChatClient() {
    running_ = false;
    connected_ = false;
    if (socket_fd_ >= 0) {
        ::shutdown(socket_fd_, SHUT_RDWR);
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
}

bool CipherChatClient::connect_to_server(const std::string& host,
                                         uint16_t port,
                                         const std::string& username) {
    host_ = host;
    port_ = port;
    username_ = username;

    socket_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        log_error("socket() failed: " + std::string(std::strerror(errno)));
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);

    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        hostent* he = gethostbyname(host_.c_str());
        if (!he || he->h_addrtype != AF_INET) {
            log_error("Unable to resolve host " + host_);
            return false;
        }
        std::memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    }

    if (::connect(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        log_error("connect() failed: " + std::string(std::strerror(errno)));
        ::close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    if (!perform_handshake()) {
        log_error("Handshake with server failed");
        ::close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    running_ = true;
    connected_ = true;
    reader_thread_ = std::thread(&CipherChatClient::reader_loop, this);
    return true;
}

bool CipherChatClient::perform_handshake() {
    auto frame_opt = receive_frame(socket_fd_);
    if (!frame_opt.has_value() || frame_opt->kind != MessageKind::Handshake) {
        return false;
    }

    std::string server_msg(frame_opt->payload.begin(), frame_opt->payload.end());
    auto server_kv = parse_kv_string(server_msg);
    if (server_kv["type"] != "server_hello") {
        return false;
    }

    auto pub_opt = base64_decode(server_kv["pub"]);
    if (!pub_opt.has_value()) {
        return false;
    }
    server_public_ = pub_opt.value();

    client_keys_ = generate_x25519_keypair();
    auto shared = compute_x25519_shared(client_keys_.private_key, server_public_);
    control_key_ = hkdf_sha256(shared, "cipherchat-control", 32);

    std::map<std::string, std::string> response{
        {"type", "client_hello"},
        {"pub", base64_encode(client_keys_.public_key)},
        {"name", username_}
    };

    Frame reply;
    reply.kind = MessageKind::Handshake;
    std::string reply_payload = kv_string(response);
    reply.payload.assign(reply_payload.begin(), reply_payload.end());
    if (!send_frame(socket_fd_, reply)) {
        return false;
    }

    auto ack_opt = receive_frame(socket_fd_);
    if (!ack_opt.has_value() || ack_opt->kind != MessageKind::Handshake) {
        return false;
    }
    std::string ack_msg(ack_opt->payload.begin(), ack_opt->payload.end());
    auto ack_kv = parse_kv_string(ack_msg);
    if (ack_kv["type"] != "handshake_ack") {
        return false;
    }
    client_id_ = static_cast<uint16_t>(std::stoi(ack_kv["id"]));
    log_info("Connected as #" + std::to_string(client_id_) + " (" + username_ + ")");
    return true;
}

void CipherChatClient::run() {
    if (!connected_) {
        std::cerr << "Not connected to any server.\n";
        return;
    }

    show_prompt();
    std::string line;
    while (running_ && std::getline(std::cin, line)) {
        if (!running_) {
            break;
        }
        process_user_input(line);
        if (!running_) {
            break;
        }
        show_prompt();
    }

    running_ = false;
    if (socket_fd_ >= 0) {
        ::shutdown(socket_fd_, SHUT_RDWR);
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
}

bool CipherChatClient::send_control(const std::map<std::string, std::string>& kv) {
    if (!connected_) {
        return false;
    }
    std::string message = kv_string(kv);
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    auto aad = control_aad(client_id_);
    auto wrapped = aes256_gcm_encrypt(control_key_, plaintext, aad);
    auto packed = pack_control_payload(wrapped.nonce, wrapped.data, wrapped.tag);
    Frame frame{MessageKind::Control, std::move(packed)};
    return send_frame(socket_fd_, frame);
}

void CipherChatClient::reader_loop() {
    while (running_) {
        auto frame_opt = receive_frame(socket_fd_);
        if (!frame_opt.has_value()) {
            log_warn("Server disconnected.");
            running_ = false;
            break;
        }
        const Frame& frame = frame_opt.value();
        if (frame.kind == MessageKind::Control) {
            handle_control_payload(frame.payload);
        } else if (frame.kind == MessageKind::ChatCipher) {
            handle_chat_payload(frame.payload);
        } else if (frame.kind == MessageKind::Handshake) {
            // Unexpected handshake message after initialization.
            std::string text(frame.payload.begin(), frame.payload.end());
            log_warn("Unexpected handshake payload: " + text);
        }
    }
}

void CipherChatClient::handle_control_payload(const std::vector<uint8_t>& payload) {
    if (client_id_ == 0) {
        return;
    }
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    if (!unpack_control_payload(payload, nonce, ciphertext, tag)) {
        log_warn("Invalid control payload from server");
        return;
    }

    Ciphertext wrapped{nonce, ciphertext, tag};
    try {
        auto aad = control_aad(client_id_);
        auto plaintext = aes256_gcm_decrypt(control_key_, wrapped, aad);
        std::string message(plaintext.begin(), plaintext.end());
        auto kv = parse_kv_string(message);
        auto type_it = kv.find("type");
        if (type_it == kv.end()) {
            return;
        }
        const std::string& type = type_it->second;
        if (type == "room_list") {
            std::cout << "\nRooms:\n";
            auto rooms_data = split(kv["rooms"], ',');
            for (const auto& entry : rooms_data) {
                if (entry.empty()) {
                    continue;
                }
                auto parts = split(entry, ':');
                if (parts.size() == 2) {
                    std::cout << "  #" << parts[0] << " - " << parts[1] << "\n";
                } else {
                    std::cout << "  " << entry << "\n";
                }
            }
            std::cout.flush();
        } else if (type == "join_ok") {
            auto id_it = kv.find("id");
            if (id_it != kv.end()) {
                current_room_id_ = static_cast<uint16_t>(std::stoi(id_it->second));
            }
            std::cout << "\nJoined room: " << kv.at("room") << std::endl;
        } else if (type == "room_key") {
            auto decoded = base64_decode(kv.at("key"));
            if (!decoded.has_value()) {
                log_warn("Failed to decode room key");
            } else {
                uint16_t id = static_cast<uint16_t>(std::stoi(kv.at("id")));
                update_room_key(kv.at("room"), id, decoded.value());
                current_room_id_ = id;
                std::cout << "\n[security] Updated key for room " << kv.at("room") << std::endl;
            }
        } else if (type == "info") {
            std::cout << "\n[info] " << kv.at("message") << std::endl;
        } else if (type == "error") {
            std::cout << "\n[error] " << kv.at("message") << std::endl;
        } else if (type == "peer_event") {
            uint16_t peer_id = static_cast<uint16_t>(std::stoi(kv.at("id")));
            const std::string& event = kv.at("event");
            const std::string& user = kv.at("user");
            if (event == "join") {
                {
                    std::lock_guard<std::mutex> lock(peer_mutex_);
                    peer_names_[peer_id] = user;
                }
                std::cout << "\n[room] " << user << " joined " << kv.at("room") << std::endl;
            } else if (event == "leave") {
                std::cout << "\n[room] " << user << " left " << kv.at("room") << std::endl;
                {
                    std::lock_guard<std::mutex> lock(peer_mutex_);
                    peer_names_.erase(peer_id);
                }
            } else if (event == "rename") {
                auto arrow_pos = user.find("->");
                std::string display = user;
                if (arrow_pos != std::string::npos) {
                    std::string new_name = trim(user.substr(arrow_pos + 2));
                    std::lock_guard<std::mutex> lock(peer_mutex_);
                    peer_names_[peer_id] = new_name;
                }
                std::cout << "\n[room] " << display << std::endl;
            }
        } else if (type == "peer_list") {
            auto room_id_str = kv.at("id");
            uint16_t room_id = static_cast<uint16_t>(std::stoi(room_id_str));
            auto entries = split(kv.at("members"), ',');
            {
                std::lock_guard<std::mutex> lock(peer_mutex_);
                for (const auto& entry : entries) {
                    if (entry.empty()) {
                        continue;
                    }
                    auto parts = split(entry, ':');
                    if (parts.size() != 2) {
                        continue;
                    }
                    uint16_t id = static_cast<uint16_t>(std::stoi(parts[0]));
                    peer_names_[id] = parts[1];
                }
            }
            std::cout << "\n[room] roster for " << kv.at("room") << ": " << kv.at("members") << std::endl;
        }
    } catch (const std::exception& ex) {
        log_error(std::string("Control decrypt failed: ") + ex.what());
    }
}

void CipherChatClient::handle_chat_payload(const std::vector<uint8_t>& payload) {
    auto env_opt = unpack_chat_envelope(payload);
    if (!env_opt.has_value()) {
        log_warn("Failed to unpack chat payload");
        return;
    }
    auto env = env_opt.value();
    auto room_opt = room_by_id(env.room_id);
    if (!room_opt.has_value()) {
        log_warn("Missing key for room id " + std::to_string(env.room_id));
        return;
    }

    Ciphertext ctx{env.nonce, env.ciphertext, env.tag};
    try {
        auto aad = chat_aad(env.room_id, env.sender_id);
        auto plaintext = aes256_gcm_decrypt(room_opt->key, ctx, aad);
        std::string message(plaintext.begin(), plaintext.end());
        std::string sender_name;
        if (env.sender_id == client_id_) {
            sender_name = username_;
        } else {
            std::lock_guard<std::mutex> lock(peer_mutex_);
            auto it = peer_names_.find(env.sender_id);
            sender_name = (it != peer_names_.end()) ? it->second : ("user#" + std::to_string(env.sender_id));
        }
        std::cout << "\n[" << room_opt->name << "] " << sender_name << ": " << message << std::endl;
    } catch (const std::exception& ex) {
        log_error(std::string("Failed to decrypt chat message: ") + ex.what());
    }
}

void CipherChatClient::process_user_input(const std::string& line) {
    std::string trimmed = trim(line);
    if (trimmed.empty()) {
        return;
    }
    if (trimmed == "/quit") {
        running_ = false;
        return;
    }
    if (trimmed == "/help") {
        std::cout << "\nCommands:\n"
                  << "  /rooms          - list rooms\n"
                  << "  /join <room>    - join or create room\n"
                  << "  /leave          - leave current room\n"
                  << "  /rename <name>  - change nickname\n"
                  << "  /quit           - exit client\n"
                  << "  <text>          - send message to current room\n";
        return;
    }
    if (trimmed == "/rooms") {
        send_control({{"type", "list"}});
        return;
    }
    if (trimmed.rfind("/join", 0) == 0) {
        auto parts = split(trimmed, ' ');
        if (parts.size() < 2) {
            std::cout << "\nUsage: /join <room>" << std::endl;
            return;
        }
        std::string room_name = parts[1];
        bool numeric = !room_name.empty() &&
                       std::all_of(room_name.begin(), room_name.end(), [](unsigned char ch) { return std::isdigit(ch); });
        if (numeric) {
            send_control({{"type", "join_id"}, {"id", room_name}});
        } else {
            send_control({{"type", "join"}, {"room", room_name}});
        }
        return;
    }
    if (trimmed == "/leave") {
        send_control({{"type", "leave"}});
        current_room_id_ = 0;
        return;
    }
    if (trimmed.rfind("/rename", 0) == 0) {
        auto parts = split(trimmed, ' ');
        if (parts.size() < 2) {
            std::cout << "\nUsage: /rename <new_name>" << std::endl;
            return;
        }
        std::string new_name = parts[1];
        username_ = new_name;
        send_control({{"type", "rename"}, {"name", new_name}});
        return;
    }

    if (current_room_id_ == 0) {
        std::cout << "\nJoin a room first with /join <room>" << std::endl;
        return;
    }
    auto room_opt = room_by_id(current_room_id_);
    if (!room_opt.has_value()) {
        std::cout << "\nMissing room key; request /join again." << std::endl;
        return;
    }

    std::vector<uint8_t> plaintext(trimmed.begin(), trimmed.end());
    auto aad = chat_aad(room_opt->id, client_id_);
    auto cipher = aes256_gcm_encrypt(room_opt->key, plaintext, aad);
    ChatCipherEnvelope env;
    env.room_id = room_opt->id;
    env.sender_id = client_id_;
    env.nonce = cipher.nonce;
    env.ciphertext = cipher.data;
    env.tag = cipher.tag;

    auto payload = pack_chat_envelope(env);
    Frame frame{MessageKind::ChatCipher, payload};
    if (!send_frame(socket_fd_, frame)) {
        log_warn("Failed to send chat message");
    }
}

std::optional<RoomKey> CipherChatClient::room_by_name(const std::string& name) {
    std::lock_guard<std::mutex> lock(room_mutex_);
    for (const auto& [id, room] : rooms_) {
        if (room.name == name) {
            return room;
        }
    }
    return std::nullopt;
}

std::optional<RoomKey> CipherChatClient::room_by_id(uint16_t id) {
    std::lock_guard<std::mutex> lock(room_mutex_);
    auto it = rooms_.find(id);
    if (it == rooms_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void CipherChatClient::update_room_key(const std::string& name,
                                       uint16_t id,
                                       const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(room_mutex_);
    RoomKey room;
    room.id = id;
    room.name = name;
    room.key = key;
    rooms_[id] = room;
}

void CipherChatClient::show_prompt() {
    std::string room_name = "?";
    if (current_room_id_ != 0) {
        auto room = room_by_id(current_room_id_);
        if (room.has_value()) {
            room_name = room->name;
        }
    }
    std::cout << "[" << room_name << "]> " << std::flush;
}

} // namespace cipherchat

