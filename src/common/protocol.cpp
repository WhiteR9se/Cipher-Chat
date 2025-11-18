/*
 * CipherChat - protocol helpers implementation
 */

#include "protocol.hpp"

#include "utils.hpp"

#include <arpa/inet.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>

namespace cipherchat {

namespace {
constexpr std::size_t kControlNonceSize = 12;
constexpr std::size_t kControlTagSize = 16;
constexpr std::size_t kChatHeaderSize = 4; // room_id (2) + sender_id (2)

bool send_all(int fd, const uint8_t* data, std::size_t len) {
    std::size_t total = 0;
    while (total < len) {
        ssize_t written = ::send(fd, data + total, len - total, 0);
        if (written <= 0) {
            return false;
        }
        total += static_cast<std::size_t>(written);
    }
    return true;
}

bool recv_all(int fd, uint8_t* data, std::size_t len) {
    std::size_t total = 0;
    while (total < len) {
        ssize_t read_bytes = ::recv(fd, data + total, len - total, MSG_WAITALL);
        if (read_bytes <= 0) {
            return false;
        }
        total += static_cast<std::size_t>(read_bytes);
    }
    return true;
}
} // namespace

bool send_frame(int socket_fd, const Frame& frame) {
    uint8_t header[5];
    header[0] = static_cast<uint8_t>(frame.kind);
    uint32_t len = htonl(static_cast<uint32_t>(frame.payload.size()));
    std::memcpy(header + 1, &len, sizeof(uint32_t));

    if (!send_all(socket_fd, header, sizeof(header))) {
        return false;
    }
    if (!frame.payload.empty()) {
        return send_all(socket_fd, frame.payload.data(), frame.payload.size());
    }
    return true;
}

std::optional<Frame> receive_frame(int socket_fd) {
    uint8_t header[5];
    if (!recv_all(socket_fd, header, sizeof(header))) {
        return std::nullopt;
    }
    MessageKind kind = static_cast<MessageKind>(header[0]);
    uint32_t len = 0;
    std::memcpy(&len, header + 1, sizeof(uint32_t));
    len = ntohl(len);

    Frame frame;
    frame.kind = kind;
    frame.payload.resize(len);
    if (len > 0) {
        if (!recv_all(socket_fd, frame.payload.data(), len)) {
            return std::nullopt;
        }
    }
    return frame;
}

std::vector<uint8_t> pack_control_payload(const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& ciphertext,
                                          const std::vector<uint8_t>& tag) {
    if (nonce.size() != kControlNonceSize || tag.size() != kControlTagSize) {
        throw std::invalid_argument("pack_control_payload: invalid nonce/tag size");
    }
    std::vector<uint8_t> payload;
    payload.reserve(nonce.size() + ciphertext.size() + tag.size());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    payload.insert(payload.end(), tag.begin(), tag.end());
    return payload;
}

bool unpack_control_payload(const std::vector<uint8_t>& payload,
                            std::vector<uint8_t>& nonce,
                            std::vector<uint8_t>& ciphertext,
                            std::vector<uint8_t>& tag) {
    if (payload.size() < kControlNonceSize + kControlTagSize) {
        return false;
    }
    nonce.assign(payload.begin(), payload.begin() + kControlNonceSize);
    tag.assign(payload.end() - kControlTagSize, payload.end());
    ciphertext.assign(payload.begin() + kControlNonceSize, payload.end() - kControlTagSize);
    return true;
}

std::vector<uint8_t> pack_chat_envelope(const ChatCipherEnvelope& env) {
    if (env.nonce.size() != kControlNonceSize || env.tag.size() != kControlTagSize) {
        throw std::invalid_argument("pack_chat_envelope: invalid nonce/tag size");
    }
    std::vector<uint8_t> payload;
    payload.reserve(kChatHeaderSize + env.nonce.size() + env.ciphertext.size() + env.tag.size());

    uint16_t room_n = htons(env.room_id);
    uint16_t sender_n = htons(env.sender_id);
    payload.push_back(static_cast<uint8_t>((room_n >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(room_n & 0xFF));
    payload.push_back(static_cast<uint8_t>((sender_n >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(sender_n & 0xFF));

    payload.insert(payload.end(), env.nonce.begin(), env.nonce.end());
    payload.insert(payload.end(), env.ciphertext.begin(), env.ciphertext.end());
    payload.insert(payload.end(), env.tag.begin(), env.tag.end());
    return payload;
}

std::optional<ChatCipherEnvelope> unpack_chat_envelope(const std::vector<uint8_t>& payload) {
    if (payload.size() < kChatHeaderSize + kControlNonceSize + kControlTagSize) {
        return std::nullopt;
    }
    ChatCipherEnvelope env;
    uint16_t room_n = static_cast<uint16_t>(payload[0] << 8 | payload[1]);
    uint16_t sender_n = static_cast<uint16_t>(payload[2] << 8 | payload[3]);
    env.room_id = ntohs(room_n);
    env.sender_id = ntohs(sender_n);

    auto nonce_begin = payload.begin() + kChatHeaderSize;
    auto nonce_end = nonce_begin + kControlNonceSize;
    env.nonce.assign(nonce_begin, nonce_end);

    auto tag_begin = payload.end() - kControlTagSize;
    env.tag.assign(tag_begin, payload.end());

    env.ciphertext.assign(nonce_end, tag_begin);
    return env;
}

} // namespace cipherchat

