/*
 * CipherChat - cryptographic helpers
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipherchat {

struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

struct Ciphertext {
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> data;
    std::vector<uint8_t> tag;
};

KeyPair generate_x25519_keypair();

std::vector<uint8_t> compute_x25519_shared(const std::vector<uint8_t>& private_key,
                                           const std::vector<uint8_t>& peer_public_key);

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& shared_secret,
                                 const std::string& info,
                                 std::size_t length);

Ciphertext aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& aad);

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const Ciphertext& ciphertext,
                                        const std::vector<uint8_t>& aad);

} // namespace cipherchat

