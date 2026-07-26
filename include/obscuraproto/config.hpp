#ifndef OBSCURAPROTO_CONFIG_HPP
#define OBSCURAPROTO_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "version.hpp"

namespace ObscuraProto {

    struct RateLimitConfig {
        bool enabled = true;
        uint32_t messages_per_second = 100;
        uint32_t burst_size = 200;
        uint32_t handshake_attempts_per_minute = 10;
        uint32_t connections_per_minute = 30;

        static RateLimitConfig defaults() {
            return RateLimitConfig{};
        }
    };

    struct ConnectionLimitConfig {
        bool enabled = true;
        uint32_t max_per_ip = 10;
        uint32_t max_total = 1000;

        static ConnectionLimitConfig defaults() {
            return ConnectionLimitConfig{};
        }
    };

    struct MessageLimitConfig {
        bool enabled = true;
        uint32_t max_ws_frame_size = 1048576;
        uint32_t max_decrypted_payload = 65535;

        static MessageLimitConfig defaults() {
            return MessageLimitConfig{};
        }
    };

    struct TimeoutConfig {
        bool enabled = true;
        uint32_t handshake_ms = 10000;
        uint32_t idle_ms = 300000;
        uint32_t check_interval_ms = 5000;

        static TimeoutConfig defaults() {
            return TimeoutConfig{};
        }
    };

    struct ReservedOpcodes {
        uint16_t RESPONSE = 0xFFFF;
        uint16_t STREAM_START = 0xFFFD;
        uint16_t STREAM_DATA = 0xFFFC;
        uint16_t STREAM_END = 0xFFFB;
        uint16_t STREAM_CANCEL = 0xFFFA;

        static ReservedOpcodes defaults() {
            return ReservedOpcodes{};
        }
    };

    struct Config {
        RateLimitConfig rate_limit;
        ConnectionLimitConfig connection_limits;
        MessageLimitConfig message_limits;
        TimeoutConfig timeouts;
        ReservedOpcodes opcodes;
        std::vector<Version> supported_versions;

        static Config from_yaml(const std::string& path);
        static Config with_defaults() {
            Config cfg{};
            cfg.supported_versions = {Versions::V1_1, Versions::V1_0};
            return cfg;
        }
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_CONFIG_HPP
