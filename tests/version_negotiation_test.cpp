#include <gtest/gtest.h>

#include "obscuraproto/version.hpp"

using namespace ObscuraProto;

TEST(VersionNegotiationTest, SuccessfulNegotiation) {
    const std::vector<Version> client_versions = {Versions::V1_0};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_0);
}

TEST(VersionNegotiationTest, PreferV1_1OverV1_0) {
    const std::vector<Version> client_versions = {Versions::V1_1, Versions::V1_0};
    const std::vector<Version> server_versions = {Versions::V1_1, Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_1);
}

TEST(VersionNegotiationTest, FallbackToV1_0) {
    const std::vector<Version> client_versions = {Versions::V1_1, Versions::V1_0};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_0);
}

TEST(VersionNegotiationTest, ClientHasOlderVersion) {
    const std::vector<Version> client_versions = {Versions::V1_0};
    const std::vector<Version> server_versions = {Versions::V1_1, Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_0);
}

TEST(VersionNegotiationTest, ServerOnlyV1_1) {
    const std::vector<Version> client_versions = {Versions::V1_1, Versions::V1_0};
    const std::vector<Version> server_versions = {Versions::V1_1};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_1);
}

TEST(VersionNegotiationTest, ClientOrderRespected) {
    const std::vector<Version> client_versions = {Versions::V1_0, Versions::V1_1};
    const std::vector<Version> server_versions = {Versions::V1_1, Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Versions::V1_0);
}

TEST(VersionNegotiationTest, NoCommonVersion) {
    constexpr Version V_UNKNOWN = 0xFFFF;
    const std::vector<Version> client_versions = {V_UNKNOWN};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}

TEST(VersionNegotiationTest, MultipleVersionsNoMatch) {
    const std::vector<Version> client_versions = {0x0200, 0x0300};
    const std::vector<Version> server_versions = {Versions::V1_1, Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}

TEST(VersionNegotiationTest, EmptyClientList) {
    const std::vector<Version> client_versions = {};
    const std::vector<Version> server_versions = {Versions::V1_0};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}

TEST(VersionNegotiationTest, EmptyServerList) {
    const std::vector<Version> client_versions = {Versions::V1_0};
    const std::vector<Version> server_versions = {};

    auto result = VersionNegotiator::negotiate(client_versions, server_versions);

    EXPECT_FALSE(result.has_value());
}
