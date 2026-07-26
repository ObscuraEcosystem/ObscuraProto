#ifndef OBSCURAPROTO_VERSION_HPP
#define OBSCURAPROTO_VERSION_HPP

#include <cstdint>
#include <optional>
#include <vector>

namespace ObscuraProto {

    // Protocol version is represented as a 16-bit integer.
    // For example, version 1.0 is 0x0100, 1.1 is 0x0101.
    using Version = uint16_t;

    namespace Versions {
        constexpr Version V1_0 = 0x0100;
        constexpr Version V1_1 = 0x0101;
    }

    // A list of supported versions, in descending order of preference.
    const std::vector<Version> SUPPORTED_VERSIONS = {Versions::V1_1, Versions::V1_0};

    /**
     * @brief Handles the logic for negotiating a common protocol version.
     */
    class VersionNegotiator {
    public:
        /**
         * @brief Selects the best common version between a client and a server.
         *
         * It iterates through the client's preferred versions and returns the first
         * one that is also present in the server's list of supported versions.
         *
         * @param client_versions A list of versions supported by the client, in descending order of preference.
         * @param server_versions A list of versions supported by the server.
         * @return The selected version, or std::nullopt if no common version is found.
         */
        static std::optional<Version> negotiate(const std::vector<Version>& client_versions,
                                                const std::vector<Version>& server_versions);
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_VERSION_HPP
