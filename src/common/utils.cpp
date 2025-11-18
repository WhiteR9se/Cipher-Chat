    /*
    * CipherChat - utility helpers implementation
    */

    #include "utils.hpp"

    #include <algorithm>
    #include <cctype>
    #include <cstring>
    #include <fstream>
    #include <iomanip>
    #include <iostream>
    #include <sstream>
    #include <stdexcept>

    #include <openssl/evp.h>
    #include <openssl/rand.h>

    namespace cipherchat {

    namespace {
    std::mutex g_log_mutex;
    LogLevel g_current_level = LogLevel::Info;

    std::string level_to_string(LogLevel level) {
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
    } // namespace

    void set_log_level(LogLevel level) {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        g_current_level = level;
    }

    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        if (static_cast<int>(level) < static_cast<int>(g_current_level)) {
            return;
        }

        auto now = std::chrono::system_clock::now();
        auto now_time = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now {};
    #if defined(_WIN32)
        localtime_s(&tm_now, &now_time);
    #else
        localtime_r(&now_time, &tm_now);
    #endif

        std::ostringstream oss;
        oss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        std::cerr << "[" << level_to_string(level) << " " << oss.str() << "] "
                << message << std::endl;
    }

    std::vector<uint8_t> random_bytes(std::size_t count) {
        std::vector<uint8_t> buffer(count);
        if (count == 0) {
            return buffer;
        }
        if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        return buffer;
    }

    std::string hex_encode(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t b : data) {
            oss << std::setw(2) << static_cast<int>(b);
        }
        return oss.str();
    }

    std::vector<uint8_t> hex_decode(const std::string& hex) {
        if (hex.size() % 2 != 0) {
            throw std::invalid_argument("hex_decode: odd length");
        }
        std::vector<uint8_t> output;
        output.reserve(hex.size() / 2);
        for (std::size_t i = 0; i < hex.size(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            output.push_back(byte);
        }
        return output;
    }

    std::string base64_encode(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            return {};
        }
        std::string output;
        output.resize(((data.size() + 2) / 3) * 4);
        int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&output[0]),
                                data.data(),
                                static_cast<int>(data.size()));
        if (len < 0) {
            throw std::runtime_error("EVP_EncodeBlock failed");
        }
        output.resize(static_cast<std::size_t>(len));
        return output;
    }

    std::optional<std::vector<uint8_t>> base64_decode(const std::string& encoded) {
        if (encoded.empty()) {
            return std::vector<uint8_t>();
        }
        std::vector<uint8_t> output;
        output.resize((encoded.size() / 4) * 3);
        int len = EVP_DecodeBlock(output.data(),
                                reinterpret_cast<const unsigned char*>(encoded.data()),
                                static_cast<int>(encoded.size()));
        if (len < 0) {
            return std::nullopt;
        }
        // Adjust for padding characters.
        std::size_t padding = 0;
        if (!encoded.empty() && encoded[encoded.size() - 1] == '=') {
            padding++;
        }
        if (encoded.size() > 1 && encoded[encoded.size() - 2] == '=') {
            padding++;
        }
        output.resize(static_cast<std::size_t>(len - padding));
        return output;
    }

    uint64_t monotonic_millis() {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    std::string kv_string(const std::map<std::string, std::string>& values) {
        std::ostringstream oss;
        bool first = true;
        for (const auto& [key, value] : values) {
            if (!first) {
                oss << ';';
            }
            first = false;
            oss << key << '=' << value;
        }
        return oss.str();
    }

    std::map<std::string, std::string> parse_kv_string(const std::string& input) {
        std::map<std::string, std::string> result;
        std::string token;
        std::istringstream iss(input);
        while (std::getline(iss, token, ';')) {
            auto pos = token.find('=');
            if (pos == std::string::npos) {
                continue;
            }
            std::string key = token.substr(0, pos);
            std::string value = token.substr(pos + 1);
            result[trim(key)] = trim(value);
        }
        return result;
    }

    std::string trim(const std::string& input) {
        auto begin = std::find_if_not(input.begin(), input.end(), [](unsigned char ch) {
            return std::isspace(ch);
        });
        auto end = std::find_if_not(input.rbegin(), input.rend(), [](unsigned char ch) {
            return std::isspace(ch);
        }).base();
        if (begin >= end) {
            return {};
        }
        return std::string(begin, end);
    }

    std::vector<std::string> split(const std::string& input, char delimiter) {
        std::vector<std::string> parts;
        std::string token;
        std::istringstream iss(input);
        while (std::getline(iss, token, delimiter)) {
            parts.push_back(token);
        }
        return parts;
    }

    FileLogger::FileLogger(std::string path) : path_(std::move(path)) {}

    FileLogger::~FileLogger() = default;

    void FileLogger::write(const std::string& line) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ofstream out(path_, std::ios::app);
        if (!out) {
            throw std::runtime_error("Failed to open log file: " + path_);
        }
        out << line << '\n';
        out.flush();
    }

    } // namespace cipherchat

