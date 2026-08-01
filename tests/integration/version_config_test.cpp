#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>

#include "../test_helpers.hpp"
#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

class VersionConfigIntegrationTest : public ::testing::Test {
protected:
    static std::atomic<uint16_t> port_counter;

    uint16_t port;
    ObscuraProto::KeyPair server_sign_key;
    ObscuraProto::KeyPair client_view_of_server_key;

    void SetUp() override {
        ASSERT_EQ(ObscuraProto::Crypto::init(), 0);
        port = port_counter.fetch_add(1);
        server_sign_key = ObscuraProto::Crypto::generate_sign_keypair();
        client_view_of_server_key.publicKey = server_sign_key.publicKey;
    }

    void TearDown() override {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
};

std::atomic<uint16_t> VersionConfigIntegrationTest::port_counter{19700};

TEST_F(VersionConfigIntegrationTest, V1_0OnlyServer) {
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.supported_versions = {ObscuraProto::Versions::V1_0};

    ObscuraProto::net::WsServerWrapper server(server_sign_key, cfg);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server.register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_FALSE(stream->get_op_code().has_value());
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "v1.0 data");
            server_got_data.set_value();
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto stream = client->start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    stream->write(ObscuraProto::byte_vector{'v', '1', '.', '0', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server.stop();
}

TEST_F(VersionConfigIntegrationTest, V1_0OnlyClient) {
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.supported_versions = {ObscuraProto::Versions::V1_0};

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server.register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_FALSE(stream->get_op_code().has_value());
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "from v1.0 client");
            server_got_data.set_value();
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, cfg);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto stream = client->start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    stream->write(
        ObscuraProto::byte_vector{'f', 'r', 'o', 'm', ' ', 'v', '1', '.', '0', ' ', 'c', 'l', 'i', 'e', 'n', 't'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server.stop();
}

TEST_F(VersionConfigIntegrationTest, V1_1OnlyBothSides) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.supported_versions = {ObscuraProto::Versions::V1_1};

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, cfg);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    std::promise<void> client_got_data;
    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        server_got_stream.set_value();
        stream->set_data_handler([stream, &server_got_data](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "v1.1 data");
            server_got_data.set_value();
            stream->write(ObscuraProto::byte_vector{'v', '1', '.', '1', ' ', 'o', 'k'});
        });
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, cfg);
    client->set_client_identity(client_identity);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto stream = client->start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string msg(data.begin(), data.end());
        EXPECT_EQ(msg, "v1.1 ok");
        client_got_data.set_value();
    });
    stream->write(ObscuraProto::byte_vector{'v', '1', '.', '1', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}

TEST_F(VersionConfigIntegrationTest, NoCommonVersion) {
    ObscuraProto::Config server_cfg = ObscuraProto::Config::with_defaults();
    server_cfg.supported_versions = {ObscuraProto::Versions::V1_1};

    ObscuraProto::Config client_cfg = ObscuraProto::Config::with_defaults();
    client_cfg.supported_versions = {ObscuraProto::Versions::V1_0};

    ObscuraProto::net::WsServerWrapper server(server_sign_key, server_cfg);
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key, client_cfg);
    std::promise<void> client_disconnected;
    std::atomic<bool> handshake_ok{false};
    client.set_on_ready_callback([&]() { handshake_ok = true; });
    client.set_on_disconnect_callback([&]() { client_disconnected.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));

    EXPECT_EQ(client_disconnected.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_FALSE(handshake_ok.load());

    server.stop();
}
