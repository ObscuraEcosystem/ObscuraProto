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

class AnonymousIntegrationTest : public ::testing::Test {
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

std::atomic<uint16_t> AnonymousIntegrationTest::port_counter{19400};

TEST_F(AnonymousIntegrationTest, AnonymousOpHandler) {
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

TEST_F(AnonymousIntegrationTest, AnonymousSyncRequest) {
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
    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload response =
        client.sync_request(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("world")).build());

    EXPECT_EQ(response.op_code, OP_ECHO);
    ObscuraProto::PayloadReader reader(response);
    EXPECT_EQ(reader.read_param<std::string>(), "echo: world");

    client.disconnect();
    server.stop();
}

TEST_F(AnonymousIntegrationTest, AnonymousAsyncRequest) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.register_anon_request_handler(
        OP_ECHO, [&](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
            std::string msg = reader.read_param<std::string>();
            return ObscuraProto::PayloadBuilder(OP_ECHO).add_param("resp: " + msg).build();
        });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto future = client.async_request(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("async")).build());

    EXPECT_EQ(future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ObscuraProto::Payload response = future.get();
    EXPECT_EQ(response.op_code, OP_ECHO);
    ObscuraProto::PayloadReader reader(response);
    EXPECT_EQ(reader.read_param<std::string>(), "resp: async");

    client.disconnect();
    server.stop();
}

TEST_F(AnonymousIntegrationTest, AnonymousServerInitiatedRequest) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_done;
    server.register_anon_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
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
    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_PING).build());

    EXPECT_EQ(client_got_request.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(server_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(AnonymousIntegrationTest, AnonymousStreaming) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    server.register_anon_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            EXPECT_EQ(msg, "anon stream data");
            server_got_data.set_value();
        });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client.start_stream(OP_ECHO);
    EXPECT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client_stream->write(
        ObscuraProto::byte_vector{'a', 'n', 'o', 'n', ' ', 's', 't', 'r', 'e', 'a', 'm', ' ', 'd', 'a', 't', 'a'});
    EXPECT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(AnonymousIntegrationTest, SendWorksForAnonymousSessions) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_send;
    server.register_anon_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader reader(payload);
        EXPECT_EQ(reader.read_param<std::string>(), "send test");
        server_got_send.set_value();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("send test")).build());

    EXPECT_EQ(server_got_send.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}
