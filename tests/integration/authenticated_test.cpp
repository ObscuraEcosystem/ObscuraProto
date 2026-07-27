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

class AuthenticatedIntegrationTest : public ::testing::Test {
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

std::atomic<uint16_t> AuthenticatedIntegrationTest::port_counter{19500};

TEST_F(AuthenticatedIntegrationTest, AuthenticatedSendReceive) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_message;
    server.set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool {
        EXPECT_EQ(pk.data, client_identity.publicKey.data);
        return true;
    });
    server.register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader reader(payload);
        EXPECT_EQ(reader.read_param<std::string>(), "auth hello");
        server_got_message.set_value();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("auth hello")).build());

    EXPECT_EQ(server_got_message.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(AuthenticatedIntegrationTest, AuthenticatedSyncRequest) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_request_handler(OP_ECHO,
                                    [&](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
                                        std::string msg = reader.read_param<std::string>();
                                        return ObscuraProto::PayloadBuilder(OP_ECHO).add_param("auth: " + msg).build();
                                    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload response =
        client.sync_request(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("world")).build());

    EXPECT_EQ(response.op_code, OP_ECHO);
    ObscuraProto::PayloadReader reader(response);
    EXPECT_EQ(reader.read_param<std::string>(), "auth: world");

    client.disconnect();
    server.stop();
}

TEST_F(AuthenticatedIntegrationTest, AuthenticatedServerInitiatedRequest) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_done;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        std::thread([&, hdl]() {
            auto future = server.async_request(
                hdl, ObscuraProto::PayloadBuilder(OP_SERVER_REQUEST).add_param(std::string("req from server")).build());
            if (future.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
                auto resp = future.get();
                ObscuraProto::PayloadReader r(resp);
                EXPECT_EQ(r.read_param<std::string>(), "resp from client");
                server_done.set_value();
            }
        }).detach();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_got_request;
    client.register_request_handler(
        OP_SERVER_REQUEST, [&](ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::string msg = reader.read_param<std::string>();
            EXPECT_EQ(msg, "req from server");
            client_got_request.set_value();
            return ObscuraProto::PayloadBuilder(OP_SERVER_REQUEST).add_param(std::string("resp from client")).build();
        });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_PING).build());

    EXPECT_EQ(client_got_request.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(server_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(AuthenticatedIntegrationTest, SendToIdentity) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> client_greeted;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_IDENTITY_GREETING, [&](auto hdl, ObscuraProto::Payload) {
        server.send_to_identity(
            client_identity.publicKey,
            ObscuraProto::PayloadBuilder(OP_IDENTITY_GREETING).add_param(std::string("hello identified!")).build());
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    client.register_op_handler(OP_IDENTITY_GREETING, [&](ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader reader(payload);
        EXPECT_EQ(reader.read_param<std::string>(), "hello identified!");
        client_greeted.set_value();
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_IDENTITY_GREETING).build());

    EXPECT_EQ(client_greeted.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(AuthenticatedIntegrationTest, IdentityRejection) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return false; });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_disconnected;
    client.set_on_disconnect_callback([&]() { client_disconnected.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));

    EXPECT_EQ(client_disconnected.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}
