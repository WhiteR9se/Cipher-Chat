/*
 * CipherChat - cryptographic helpers implementation
 */

#include "crypto.hpp"

#include "utils.hpp"

#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace cipherchat {

namespace {
constexpr std::size_t kX25519KeySize = 32;
constexpr std::size_t kAes256KeySize = 32;
constexpr std::size_t kGcmNonceSize = 12;
constexpr std::size_t kGcmTagSize = 16;
} // namespace

KeyPair generate_x25519_keypair() {
    KeyPair kp;
    kp.public_key.resize(kX25519KeySize);
    kp.private_key.resize(kX25519KeySize);

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!context) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_keygen(context, &params) <= 0) {
        EVP_PKEY_CTX_free(context);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }

    std::size_t pub_len = kX25519KeySize;
    std::size_t priv_len = kX25519KeySize;
    if (EVP_PKEY_get_raw_public_key(params, kp.public_key.data(), &pub_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(params, kp.private_key.data(), &priv_len) <= 0) {
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(context);
        throw std::runtime_error("Failed to extract X25519 key material");
    }
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(context);
    return kp;
}

std::vector<uint8_t> compute_x25519_shared(const std::vector<uint8_t>& private_key,
                                           const std::vector<uint8_t>& peer_public_key) {
    if (private_key.size() != kX25519KeySize || peer_public_key.size() != kX25519KeySize) {
        throw std::invalid_argument("X25519 keys must be 32 bytes");
    }

    EVP_PKEY* my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,
                                                    nullptr,
                                                    private_key.data(),
                                                    private_key.size());
    if (!my_key) {
        throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
    }

    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                                     nullptr,
                                                     peer_public_key.data(),
                                                     peer_public_key.size());
    if (!peer_key) {
        EVP_PKEY_free(my_key);
        throw std::runtime_error("EVP_PKEY_new_raw_public_key failed");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("EVP_PKEY_derive init failed");
    }

    std::size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("EVP_PKEY_derive length query failed");
    }

    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("EVP_PKEY_derive failed");
    }
    secret.resize(secret_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);
    return secret;
}

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& shared_secret,
                                 const std::string& info,
                                 std::size_t length) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id(HKDF) failed");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx,
                                    reinterpret_cast<const unsigned char*>(""),
                                    0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret.data(), shared_secret.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                    reinterpret_cast<const unsigned char*>(info.data()),
                                    info.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF setup failed");
    }

    std::vector<uint8_t> output(length);
    if (EVP_PKEY_derive(ctx, output.data(), &length) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF derive failed");
    }
    output.resize(length);
    EVP_PKEY_CTX_free(ctx);
    return output;
}

Ciphertext aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& plaintext,
                              const std::vector<uint8_t>& aad) {
    if (key.size() != kAes256KeySize) {
        throw std::invalid_argument("AES-256 key must be 32 bytes");
    }

    Ciphertext result;
    result.nonce = random_bytes(kGcmNonceSize);
    result.data.resize(plaintext.size());
    result.tag.resize(kGcmTagSize);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceSize, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM init failed");
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx,
                              nullptr,
                              &len,
                              aad.data(),
                              static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-GCM AAD update failed");
        }
    }

    if (EVP_EncryptUpdate(ctx,
                          result.data.data(),
                          &len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encrypt failed");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx,
                            result.data.data() + len,
                            &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM finalization failed");
    }
    ciphertext_len += len;
    result.data.resize(static_cast<std::size_t>(ciphertext_len));

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_GET_TAG,
                            kGcmTagSize,
                            result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM get tag failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const Ciphertext& ciphertext,
                                        const std::vector<uint8_t>& aad) {
    if (key.size() != kAes256KeySize) {
        throw std::invalid_argument("AES-256 key must be 32 bytes");
    }
    if (ciphertext.nonce.size() != kGcmNonceSize ||
        ciphertext.tag.size() != kGcmTagSize) {
        throw std::invalid_argument("Invalid AES-GCM parameters");
    }

    std::vector<uint8_t> plaintext(ciphertext.data.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceSize, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), ciphertext.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM decrypt init failed");
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx,
                              nullptr,
                              &len,
                              aad.data(),
                              static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-GCM decrypt AAD update failed");
        }
    }

    if (EVP_DecryptUpdate(ctx,
                          plaintext.data(),
                          &len,
                          ciphertext.data.data(),
                          static_cast<int>(ciphertext.data.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM decrypt failed");
    }
    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            kGcmTagSize,
                            const_cast<unsigned char*>(ciphertext.tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM set tag failed");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM authentication failed");
    }
    plaintext_len += len;
    plaintext.resize(static_cast<std::size_t>(plaintext_len));

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

} // namespace cipherchat

