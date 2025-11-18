/*
 * CipherChat - protocol helpers header
 *
 * This header defines the data structures and helper functions used for
 * encoding, decoding, and transmitting CipherChat protocol messages.
 *
 * It provides interfaces for message framing, control message packing and
 * unpacking, and the chat ciphertext envelope format. These functions handle
 * serialization and deserialization of network payloads used between clients
 * and the server.
 *
 * Implementations are provided separately in /src/protocol.cpp.
 */


#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace cipherchat {

enum class MessageKind : uint8_t {
    Handshake = 0x01,
    Control = 0x10,
    ChatCipher = 0x20
};

struct Frame {
    MessageKind kind;
    std::vector<uint8_t> payload;
};

bool send_frame(int socket_fd, const Frame& frame);

std::optional<Frame> receive_frame(int socket_fd);

std::vector<uint8_t> pack_control_payload(const std::vector<uint8_t>& nonce,
                                          const std::vector<uint8_t>& ciphertext,
                                          const std::vector<uint8_t>& tag);

bool unpack_control_payload(const std::vector<uint8_t>& payload,
                            std::vector<uint8_t>& nonce,
                            std::vector<uint8_t>& ciphertext,
                            std::vector<uint8_t>& tag);

struct ChatCipherEnvelope {
    uint16_t room_id;
    uint16_t sender_id;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

std::vector<uint8_t> pack_chat_envelope(const ChatCipherEnvelope& env);

std::optional<ChatCipherEnvelope> unpack_chat_envelope(const std::vector<uint8_t>& payload);

} // namespace cipherchat

