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

class StreamRoutingIntegrationTest : public ::testing::Test {
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

std::atomic<uint16_t> StreamRoutingIntegrationTest::port_counter{19600};

TEST_F(StreamRoutingIntegrationTest, OpCodeSpecificStreamRouting) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
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
            EXPECT_EQ(msg, "hello from client");
            server_got_data.set_value();
            stream->write(ObscuraProto::byte_vector{'w', 'o', 'r', 'l', 'd'});
        });
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    client->set_client_identity(client_identity);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client->start_stream(OP_ECHO);
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

    client->disconnect();
    server->stop();
}

TEST_F(StreamRoutingIntegrationTest, FallbackToGenericStreamHandler) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    constexpr uint16_t OP_NO_HANDLER = 0x9001;

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_NO_HANDLER);
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "fallback data");
            server_got_data.set_value();
        });
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    client->set_client_identity(client_identity);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client->start_stream(OP_NO_HANDLER);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client_stream->write(ObscuraProto::byte_vector{'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}

TEST_F(StreamRoutingIntegrationTest, BackwardCompatibleStartStream) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
    std::promise<void> server_got_data;
    std::promise<void> client_got_data;
    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_FALSE(stream->get_op_code().has_value());
        stream->set_data_handler([stream, &server_got_data](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "hello");
            server_got_data.set_value();
            stream->write(ObscuraProto::byte_vector{'e', 'c', 'h', 'o'});
        });
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    client->set_client_identity(client_identity);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client->start_stream();
    client_stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string msg(data.begin(), data.end());
        EXPECT_EQ(msg, "echo");
        client_got_data.set_value();
    });
    client_stream->write(ObscuraProto::byte_vector{'h', 'e', 'l', 'l', 'o'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}

TEST_F(StreamRoutingIntegrationTest, AnonymousStreamRouting) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server->register_anon_stream_handler(OP_PING, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_PING);
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "anon data");
            server_got_data.set_value();
        });
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client->start_stream(OP_PING);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client_stream->write(ObscuraProto::byte_vector{'a', 'n', 'o', 'n', ' ', 'd', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}

TEST_F(StreamRoutingIntegrationTest, ServerInitiatedOpCodeStream) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::net::WsConnectionHdl client_hdl;

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
    std::promise<void> server_got_ready;
    std::promise<void> client_got_stream;
    std::promise<void> client_got_data;
    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        client_hdl = hdl;
        server_got_ready.set_value();
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    client->set_client_identity(client_identity);
    client->register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
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
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->send(ObscuraProto::PayloadBuilder(OP_PING).build());
    ASSERT_EQ(server_got_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto server_stream = server->start_stream(client_hdl, OP_ECHO);
    ASSERT_EQ(client_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    server_stream->write(ObscuraProto::byte_vector{'f', 'r', 'o', 'm', ' ', 's', 'e', 'r', 'v', 'e', 'r'});
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}

TEST_F(StreamRoutingIntegrationTest, AnonServerInitiatedOpCodeStream) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
    std::promise<void> client_got_stream;
    std::promise<void> client_got_data;
    server->register_anon_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        auto server_stream = server->start_stream(hdl, OP_ECHO);
        server_stream->write(
            ObscuraProto::byte_vector{'a', 'n', 'o', 'n', ' ', 's', 'r', 'v', ' ', 'd', 'a', 't', 'a'});
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    client->register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
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
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->send(ObscuraProto::PayloadBuilder(OP_PING).build());
    ASSERT_EQ(client_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}

TEST_F(StreamRoutingIntegrationTest, ClientDataHandlerCanStartNewStream) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key);
    std::promise<void> server_got_nested_stream;
    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        stream->set_data_handler([stream](const ObscuraProto::byte_vector& data) { stream->write(data); });
    });
    server->register_stream_handler(OP_PING, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        server_got_nested_stream.set_value();
        stream->set_data_handler([stream](const ObscuraProto::byte_vector& data) { stream->write(data); });
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
    client->set_client_identity(client_identity);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    std::promise<void> client_got_echo;
    auto client_stream = client->start_stream(OP_ECHO);
    client_stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        // Re-entrant call from a user handler: start_stream() must not deadlock.
        auto nested_stream = client->start_stream(OP_PING);
        EXPECT_EQ(nested_stream->get_op_code().value(), OP_PING);
        client_got_echo.set_value();
    });
    client_stream->write(ObscuraProto::byte_vector{'p', 'i', 'n', 'g'});

    ASSERT_EQ(client_got_echo.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(server_got_nested_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client->disconnect();
    server->stop();
}
