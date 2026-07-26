#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

// Shared opcodes for tests
constexpr uint16_t OP_ECHO = 0x8001;
constexpr uint16_t OP_PING = 0x8002;
constexpr uint16_t OP_IDENTITY_GREETING = 0x8003;
constexpr uint16_t OP_SERVER_REQUEST = 0x8004;

class WsIntegrationTest : public ::testing::Test {
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

std::atomic<uint16_t> WsIntegrationTest::port_counter{19100};

// ========== Anonymous session tests ==========

TEST_F(WsIntegrationTest, AnonymousOpHandler) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_message;
    server.register_anon_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader reader(payload);
        EXPECT_EQ(reader.read_param<std::string>(), "hello");
        server_got_message.set_value();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));

    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("hello")).build());

    EXPECT_EQ(server_got_message.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, AnonymousSyncRequest) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.register_anon_request_handler(
        OP_ECHO, [&](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::string msg = reader.read_param<std::string>();
            return ObscuraProto::PayloadBuilder(OP_ECHO).add_param("echo: " + msg).build();
        });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload response =
        client.sync_request(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("world")).build());

    EXPECT_EQ(response.op_code, OP_ECHO);
    ObscuraProto::PayloadReader reader(response);
    EXPECT_EQ(reader.read_param<std::string>(), "echo: world");

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, AnonymousAsyncRequest) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.register_anon_request_handler(
        OP_ECHO, [&](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::string msg = reader.read_param<std::string>();
            return ObscuraProto::PayloadBuilder(OP_ECHO).add_param("async: " + msg).build();
        });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto future = client.async_request(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("test")).build());

    ASSERT_EQ(future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ObscuraProto::Payload response = future.get();
    EXPECT_EQ(response.op_code, OP_ECHO);
    ObscuraProto::PayloadReader reader(response);
    EXPECT_EQ(reader.read_param<std::string>(), "async: test");

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, AnonymousServerInitiatedRequest) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_done;

    // Register anon handler: when client sends OP_PING, server replies and also sends its own request
    server.register_anon_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload payload) {
        std::thread([&, hdl]() {
            auto server_future = server.async_request(
                hdl, ObscuraProto::PayloadBuilder(OP_SERVER_REQUEST).add_param(std::string("from server")).build());
            if (server_future.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
                server_done.set_value();
            }
        }).detach();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_got_request;
    client.register_request_handler(
        OP_SERVER_REQUEST, [&](ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::string msg = reader.read_param<std::string>();
            EXPECT_EQ(msg, "from server");
            client_got_request.set_value();
            return ObscuraProto::PayloadBuilder(OP_SERVER_REQUEST).add_param(std::string("client response")).build();
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

TEST_F(WsIntegrationTest, AnonymousStreaming) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<std::string> server_received_promise;
    auto server_received_future = server_received_promise.get_future();
    server.register_incoming_stream_handler([&server_received_promise](std::shared_ptr<ObscuraProto::Stream> stream) {
        stream->set_data_handler([stream, &server_received_promise](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            server_received_promise.set_value(msg);
            stream->write(data);
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_got_echo_promise;
    auto client_got_echo_future = client_got_echo_promise.get_future();

    client.set_on_ready_callback([&]() {
        auto client_stream = client.start_stream();
        client_stream->set_data_handler([&client_got_echo_promise](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "hello");
            client_got_echo_promise.set_value();
        });
        client_stream->write(ObscuraProto::byte_vector{'h', 'e', 'l', 'l', 'o'});
    });
    client.connect("ws://localhost:" + std::to_string(port));

    ASSERT_EQ(server_received_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(server_received_future.get(), "hello");
    ASSERT_EQ(client_got_echo_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, SendWorksForAnonymousSessions) {
    // This tests the fix: server.send(hdl, p) must work for anon sessions
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> client_received_response;
    server.register_anon_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        // Use the general send() (not send_anonymous()) — this should still work
        server.send(hdl, ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("pong")).build());
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.register_op_handler(OP_ECHO, [&](ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader reader(payload);
        EXPECT_EQ(reader.read_param<std::string>(), "pong");
        client_received_response.set_value();
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).build());

    EXPECT_EQ(client_received_response.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

// ========== Authenticated session tests ==========

TEST_F(WsIntegrationTest, AuthenticatedSendReceive) {
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

TEST_F(WsIntegrationTest, AuthenticatedSyncRequest) {
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

TEST_F(WsIntegrationTest, AuthenticatedServerInitiatedRequest) {
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

TEST_F(WsIntegrationTest, SendToIdentity) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> client_greeted;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_IDENTITY_GREETING, [&](auto hdl, ObscuraProto::Payload) {
        // Send a response using the client's identity key
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

TEST_F(WsIntegrationTest, IdentityRejection) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool {
        return false;  // reject all
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_disconnected;
    client.set_on_disconnect_callback([&]() { client_disconnected.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));

    // Client should NOT get a ready callback (handshake completes but server rejects)
    // Instead, disconnect/fail should fire
    EXPECT_EQ(client_disconnected.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

// ========== OpCode Stream Routing Tests ==========

TEST_F(WsIntegrationTest, OpCodeSpecificStreamRouting) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    std::promise<void> client_got_data;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        server_got_stream.set_value();
        stream->set_data_handler([stream, &server_got_data](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "hello from client");
            server_got_data.set_value();
            stream->write(ObscuraProto::byte_vector{'w', 'o', 'r', 'l', 'd'});
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client.start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client_stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string msg(data.begin(), data.end());
        EXPECT_EQ(msg, "world");
        client_got_data.set_value();
    });
    client_stream->write(
        ObscuraProto::byte_vector{'h', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'c', 'l', 'i', 'e', 'n', 't'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, FallbackToGenericStreamHandler) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    constexpr uint16_t OP_NO_HANDLER = 0x9001;

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_NO_HANDLER);
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "fallback data");
            server_got_data.set_value();
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client.start_stream(OP_NO_HANDLER);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client_stream->write(ObscuraProto::byte_vector{'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, BackwardCompatibleStartStream) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_data;
    std::promise<void> client_got_data;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_FALSE(stream->get_op_code().has_value());
        stream->set_data_handler([stream, &server_got_data](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "hello");
            server_got_data.set_value();
            stream->write(ObscuraProto::byte_vector{'e', 'c', 'h', 'o'});
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client.start_stream();
    client_stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string msg(data.begin(), data.end());
        EXPECT_EQ(msg, "echo");
        client_got_data.set_value();
    });
    client_stream->write(ObscuraProto::byte_vector{'h', 'e', 'l', 'l', 'o'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, AnonymousStreamRouting) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server.register_anon_stream_handler(OP_PING, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_PING);
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "anon data");
            server_got_data.set_value();
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client.start_stream(OP_PING);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client_stream->write(ObscuraProto::byte_vector{'a', 'n', 'o', 'n', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, ServerInitiatedOpCodeStream) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::net::WsConnectionHdl client_hdl;

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_ready;
    std::promise<void> client_got_stream;
    std::promise<void> client_got_data;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        client_hdl = hdl;
        server_got_ready.set_value();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    client.register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        client_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "from server");
            client_got_data.set_value();
        });
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_PING).build());
    ASSERT_EQ(server_got_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto server_stream = server.start_stream(client_hdl, OP_ECHO);
    ASSERT_EQ(client_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    server_stream->write(ObscuraProto::byte_vector{'f', 'r', 'o', 'm', ' ', 's', 'e', 'r', 'v', 'e', 'r'});
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, AnonServerInitiatedOpCodeStream) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> client_got_stream;
    std::promise<void> client_got_data;
    server.register_anon_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        auto server_stream = server.start_stream(hdl, OP_ECHO);
        server_stream->write(
            ObscuraProto::byte_vector{'a', 'n', 'o', 'n', ' ', 's', 'r', 'v', ' ', 'd', 'a', 't', 'a'});
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        client_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "anon srv data");
            client_got_data.set_value();
        });
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_PING).build());
    ASSERT_EQ(client_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

// ========== Version configuration tests ==========

TEST_F(WsIntegrationTest, V1_0OnlyServer) {
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

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto stream = client.start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    stream->write(ObscuraProto::byte_vector{'v', '1', '.', '0', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, V1_0OnlyClient) {
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

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key, cfg);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto stream = client.start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    stream->write(
        ObscuraProto::byte_vector{'f', 'r', 'o', 'm', ' ', 'v', '1', '.', '0', ' ', 'c', 'l', 'i', 'e', 'n', 't'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, V1_1OnlyBothSides) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.supported_versions = {ObscuraProto::Versions::V1_1};

    ObscuraProto::net::WsServerWrapper server(server_sign_key, cfg);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    std::promise<void> client_got_data;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
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
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key, cfg);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto stream = client.start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string msg(data.begin(), data.end());
        EXPECT_EQ(msg, "v1.1 ok");
        client_got_data.set_value();
    });
    stream->write(ObscuraProto::byte_vector{'v', '1', '.', '1', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsIntegrationTest, NoCommonVersion) {
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
