/*
 * CipherChat - utility helpers
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace cipherchat {

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error
};

void set_log_level(LogLevel level);

void log(LogLevel level, const std::string& message);

inline void log_info(const std::string& message) {
    log(LogLevel::Info, message);
}

inline void log_warn(const std::string& message) {
    log(LogLevel::Warn, message);
}

inline void log_error(const std::string& message) {
    log(LogLevel::Error, message);
}

inline void log_debug(const std::string& message) {
    log(LogLevel::Debug, message);
}

std::vector<uint8_t> random_bytes(std::size_t count);

std::string hex_encode(const std::vector<uint8_t>& data);

std::vector<uint8_t> hex_decode(const std::string& hex);

std::string base64_encode(const std::vector<uint8_t>& data);

std::optional<std::vector<uint8_t>> base64_decode(const std::string& encoded);

uint64_t monotonic_millis();

std::string kv_string(const std::map<std::string, std::string>& values);

std::map<std::string, std::string> parse_kv_string(const std::string& input);

std::string trim(const std::string& input);

std::vector<std::string> split(const std::string& input, char delimiter);

class FileLogger {
public:
    explicit FileLogger(std::string path);
    ~FileLogger();

    void write(const std::string& line);

private:
    std::string path_;
    std::mutex mutex_;
};

} // namespace cipherchat

