#include "obscuraproto/config.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace ObscuraProto {

    namespace {

        std::string trim(const std::string& s) {
            size_t start = 0;
            while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) {
                ++start;
            }
            size_t end = s.size();
            while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r')) {
                --end;
            }
            return s.substr(start, end - start);
        }

        // Parse a YAML line. Returns true if key was set.
        // Sets section, key, and value. Section tracks nesting.
        bool parse_yaml_line(const std::string& line, std::string& section, std::string& key, std::string& value) {
            // Strip comment
            size_t comment = line.find('#');
            std::string content = (comment != std::string::npos) ? line.substr(0, comment) : line;
            content = trim(content);
            if (content.empty()) {
                return false;
            }

            size_t colon = content.find(':');
            if (colon == std::string::npos) {
                return false;
            }

            std::string before = trim(content.substr(0, colon));
            std::string after = trim(content.substr(colon + 1));

            if (after.empty()) {
                // Section header (e.g., "server:" or "  rate_limiting:")
                // Overwrite section based on indentation
                size_t indent = 0;
                size_t raw_pos = line.find_first_not_of(" \t");
                if (raw_pos != std::string::npos) {
                    // We detect depth: 0 spaces = top, 2 spaces = level 1, 4 spaces = level 2
                    while (indent < raw_pos && (line[indent] == ' ' || line[indent] == '\t')) {
                        ++indent;
                    }
                }
                // Simple rule: no indent = new top section
                //          2 spaces = sub-section of current top section
                //          4 spaces = not used in our config
                if (indent == 0) {
                    section = before;
                } else {
                    section = before;
                    // The parent section is lost, but we only use the current section name for "enabled" context
                }
                key.clear();
                value.clear();
                return false;
            }

            key = before;
            value = after;
            return true;
        }

        uint32_t parse_uint32(const std::string& s) {
            if (s.empty()) {
                return 0;
            }
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                return static_cast<uint32_t>(std::stoul(s, nullptr, 16));
            }
            return static_cast<uint32_t>(std::stoul(s));
        }

    }  // anonymous namespace

    Config Config::from_yaml(const std::string& path) {
        Config cfg;

        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "[ObscuraProto] Warning: could not open config file '" << path << "'. Using defaults."
                      << std::endl;
            return cfg;
        }

        std::string section;
        std::string line;
        int line_num = 0;

        while (std::getline(file, line)) {
            ++line_num;
            std::string key, value;
            if (!parse_yaml_line(line, section, key, value)) {
                continue;
            }

            try {
                if (key == "enabled") {
                    bool v = (value == "true" || value == "yes" || value == "1");
                    if (section == "rate_limiting") {
                        cfg.rate_limit.enabled = v;
                    } else if (section == "connection_limits") {
                        cfg.connection_limits.enabled = v;
                    } else if (section == "message_limits") {
                        cfg.message_limits.enabled = v;
                    } else if (section == "timeouts") {
                        cfg.timeouts.enabled = v;
                    }
                } else if (key == "messages_per_second") {
                    cfg.rate_limit.messages_per_second = parse_uint32(value);
                } else if (key == "burst_size") {
                    cfg.rate_limit.burst_size = parse_uint32(value);
                } else if (key == "handshake_attempts_per_minute") {
                    cfg.rate_limit.handshake_attempts_per_minute = parse_uint32(value);
                } else if (key == "connections_per_minute") {
                    cfg.rate_limit.connections_per_minute = parse_uint32(value);
                } else if (key == "max_per_ip") {
                    cfg.connection_limits.max_per_ip = parse_uint32(value);
                } else if (key == "max_total") {
                    cfg.connection_limits.max_total = parse_uint32(value);
                } else if (key == "max_ws_frame_size") {
                    cfg.message_limits.max_ws_frame_size = parse_uint32(value);
                } else if (key == "max_decrypted_payload") {
                    cfg.message_limits.max_decrypted_payload = parse_uint32(value);
                } else if (key == "handshake_ms") {
                    cfg.timeouts.handshake_ms = parse_uint32(value);
                } else if (key == "idle_ms") {
                    cfg.timeouts.idle_ms = parse_uint32(value);
                } else if (key == "check_interval_ms") {
                    cfg.timeouts.check_interval_ms = parse_uint32(value);
                } else if (key == "RESPONSE") {
                    cfg.opcodes.RESPONSE = static_cast<uint16_t>(parse_uint32(value));
                } else if (key == "STREAM_START") {
                    cfg.opcodes.STREAM_START = static_cast<uint16_t>(parse_uint32(value));
                } else if (key == "STREAM_DATA") {
                    cfg.opcodes.STREAM_DATA = static_cast<uint16_t>(parse_uint32(value));
                } else if (key == "STREAM_END") {
                    cfg.opcodes.STREAM_END = static_cast<uint16_t>(parse_uint32(value));
                } else if (key == "STREAM_CANCEL") {
                    cfg.opcodes.STREAM_CANCEL = static_cast<uint16_t>(parse_uint32(value));
                } else if (key == "supported_versions") {
                    // Format: [0x0101, 0x0100]
                    std::vector<Version> versions;
                    size_t pos = 0;
                    while (pos < value.size()) {
                        // Find next hex number after '[' or ',' or space
                        auto start = value.find_first_of("0123456789xXabcdefABCDEF", pos);
                        if (start == std::string::npos)
                            break;
                        auto end = value.find_first_not_of("0123456789xXabcdefABCDEF", start);
                        if (end == std::string::npos)
                            end = value.size();
                        std::string num_str = value.substr(start, end - start);
                        versions.push_back(static_cast<Version>(std::stoul(num_str, nullptr, 16)));
                        pos = end;
                    }
                    if (!versions.empty()) {
                        cfg.supported_versions = versions;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[ObscuraProto] Warning: invalid value at line " << line_num << " ('" << value
                          << "'): " << e.what() << std::endl;
            }
        }

        return cfg;
    }

}  // namespace ObscuraProto
