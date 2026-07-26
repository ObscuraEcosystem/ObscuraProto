#include "obscuraproto/config.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>

namespace ObscuraProto {
    namespace {

        TEST(ConfigTest, DefaultsAreSane) {
            Config cfg = Config::with_defaults();

            EXPECT_TRUE(cfg.rate_limit.enabled);
            EXPECT_EQ(cfg.rate_limit.messages_per_second, 100u);
            EXPECT_EQ(cfg.rate_limit.burst_size, 200u);
            EXPECT_EQ(cfg.rate_limit.handshake_attempts_per_minute, 10u);
            EXPECT_EQ(cfg.rate_limit.connections_per_minute, 30u);

            EXPECT_TRUE(cfg.connection_limits.enabled);
            EXPECT_EQ(cfg.connection_limits.max_per_ip, 10u);
            EXPECT_EQ(cfg.connection_limits.max_total, 1000u);

            EXPECT_TRUE(cfg.message_limits.enabled);
            EXPECT_EQ(cfg.message_limits.max_ws_frame_size, 1048576u);
            EXPECT_EQ(cfg.message_limits.max_decrypted_payload, 65535u);

            EXPECT_TRUE(cfg.timeouts.enabled);
            EXPECT_EQ(cfg.timeouts.handshake_ms, 10000u);
            EXPECT_EQ(cfg.timeouts.idle_ms, 300000u);
            EXPECT_EQ(cfg.timeouts.check_interval_ms, 5000u);

            EXPECT_EQ(cfg.opcodes.RESPONSE, 0xFFFF);
            EXPECT_EQ(cfg.opcodes.STREAM_START, 0xFFFD);
            EXPECT_EQ(cfg.opcodes.STREAM_DATA, 0xFFFC);
            EXPECT_EQ(cfg.opcodes.STREAM_END, 0xFFFB);
            EXPECT_EQ(cfg.opcodes.STREAM_CANCEL, 0xFFFA);

            ASSERT_EQ(cfg.supported_versions.size(), 2u);
            EXPECT_EQ(cfg.supported_versions[0], Versions::V1_1);
            EXPECT_EQ(cfg.supported_versions[1], Versions::V1_0);
        }

        std::string write_test_yaml(const std::string& content) {
            auto tmp_path = std::filesystem::temp_directory_path() /
                            ("obscuraproto_config_test_" + std::to_string(std::random_device{}()));
            std::ofstream file(tmp_path);
            file << content;
            file.close();
            return tmp_path.string();
        }

        TEST(ConfigTest, LoadsFromYaml) {
            std::string yaml = R"(
server:
  rate_limiting:
    enabled: true
    messages_per_second: 50
    burst_size: 100
    handshake_attempts_per_minute: 5
    connections_per_minute: 15

  connection_limits:
    enabled: true
    max_per_ip: 5
    max_total: 500

  message_limits:
    enabled: false
    max_ws_frame_size: 0
    max_decrypted_payload: 0

  timeouts:
    enabled: true
    handshake_ms: 5000
    idle_ms: 60000
    check_interval_ms: 2000

opcodes:
  RESPONSE: 0xF0F0
  STREAM_START: 0xF0F1
)";
            std::string path = write_test_yaml(yaml);

            Config cfg = Config::from_yaml(path);
            std::remove(path.c_str());

            EXPECT_TRUE(cfg.rate_limit.enabled);
            EXPECT_EQ(cfg.rate_limit.messages_per_second, 50u);
            EXPECT_EQ(cfg.rate_limit.burst_size, 100u);
            EXPECT_EQ(cfg.rate_limit.handshake_attempts_per_minute, 5u);
            EXPECT_EQ(cfg.rate_limit.connections_per_minute, 15u);

            EXPECT_TRUE(cfg.connection_limits.enabled);
            EXPECT_EQ(cfg.connection_limits.max_per_ip, 5u);
            EXPECT_EQ(cfg.connection_limits.max_total, 500u);

            EXPECT_FALSE(cfg.message_limits.enabled);
            EXPECT_EQ(cfg.message_limits.max_ws_frame_size, 0u);
            EXPECT_EQ(cfg.message_limits.max_decrypted_payload, 0u);

            EXPECT_TRUE(cfg.timeouts.enabled);
            EXPECT_EQ(cfg.timeouts.handshake_ms, 5000u);
            EXPECT_EQ(cfg.timeouts.idle_ms, 60000u);
            EXPECT_EQ(cfg.timeouts.check_interval_ms, 2000u);

            EXPECT_EQ(cfg.opcodes.RESPONSE, 0xF0F0);
            EXPECT_EQ(cfg.opcodes.STREAM_START, 0xF0F1);
            // Unset opcodes should keep defaults
            EXPECT_EQ(cfg.opcodes.STREAM_DATA, 0xFFFCu);
            EXPECT_EQ(cfg.opcodes.STREAM_END, 0xFFFBu);
            EXPECT_EQ(cfg.opcodes.STREAM_CANCEL, 0xFFFAu);
        }

        TEST(ConfigTest, LoadsSupportedVersionsFromYaml) {
            std::string yaml = R"(
server:
  supported_versions: [0x0101, 0x0100]
)";
            std::string path = write_test_yaml(yaml);
            Config cfg = Config::from_yaml(path);
            std::remove(path.c_str());

            ASSERT_EQ(cfg.supported_versions.size(), 2u);
            EXPECT_EQ(cfg.supported_versions[0], Versions::V1_1);
            EXPECT_EQ(cfg.supported_versions[1], Versions::V1_0);
        }

        TEST(ConfigTest, LoadsSingleVersionFromYaml) {
            std::string yaml = R"(
server:
  supported_versions: [0x0100]
)";
            std::string path = write_test_yaml(yaml);
            Config cfg = Config::from_yaml(path);
            std::remove(path.c_str());

            ASSERT_EQ(cfg.supported_versions.size(), 1u);
            EXPECT_EQ(cfg.supported_versions[0], Versions::V1_0);
        }

        TEST(ConfigTest, MissingFileUsesDefaults) {
            Config cfg = Config::from_yaml("/tmp/nonexistent_obscuraproto_config_xyz.yml");
            Config defaults = Config::with_defaults();

            EXPECT_EQ(cfg.rate_limit.enabled, defaults.rate_limit.enabled);
            EXPECT_EQ(cfg.rate_limit.messages_per_second, defaults.rate_limit.messages_per_second);
            EXPECT_EQ(cfg.opcodes.RESPONSE, defaults.opcodes.RESPONSE);
        }

    }  // namespace
}  // namespace ObscuraProto
