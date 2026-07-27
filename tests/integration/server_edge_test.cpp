#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "../test_helpers.hpp"
#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

class ServerEdgeIntegrationTest : public ::testing::Test {
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

std::atomic<uint16_t> ServerEdgeIntegrationTest::port_counter{19900};

TEST_F(ServerEdgeIntegrationTest, StreamEndAndCancel) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_stream;
    std::promise<void> server_got_data;
    std::promise<void> server_got_end;
    std::promise<void> client_got_cancel;

    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        server_got_stream.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) { server_got_data.set_value(); });
        stream->set_end_handler([&]() { server_got_end.set_value(); });
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    client.register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        stream->set_cancel_handler([&]() { client_got_cancel.set_value(); });
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client.start_stream(OP_ECHO);
    ASSERT_EQ(server_got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    client_stream->write(ObscuraProto::byte_vector{'d', 'a', 't', 'a'});
    ASSERT_EQ(server_got_data.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    client_stream->end();
    ASSERT_EQ(server_got_end.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    std::promise<void> server_ping;
    std::promise<void> client_stream2_ready;
    client.register_stream_handler(OP_PING, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        stream->set_cancel_handler([&]() { client_got_cancel.set_value(); });
        client_stream2_ready.set_value();
    });
    server.register_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        auto srv_stream = server.start_stream(hdl, OP_PING);
        srv_stream->cancel();
        server_ping.set_value();
    });
    client.send(ObscuraProto::PayloadBuilder(OP_PING).build());
    ASSERT_EQ(server_ping.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_stream2_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(client_got_cancel.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, ServerSyncRequest) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_done;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_PING, [&](auto hdl, ObscuraProto::Payload) {
        std::thread([&, hdl]() {
            ObscuraProto::Payload resp = server.sync_request(
                hdl, ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("server sync")).build());
            EXPECT_EQ(resp.op_code, OP_PING);
            ObscuraProto::PayloadReader r(resp);
            EXPECT_EQ(r.read_param<std::string>(), "pong from client");
            server_done.set_value();
        }).detach();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    client.register_request_handler(OP_PING, [&](ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "server sync");
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong from client")).build();
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_PING).build());
    EXPECT_EQ(server_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, ServerRequestToIdentity) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_done_sync;
    std::promise<void> server_done_async;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload) {
        std::thread([&]() {
            ObscuraProto::Payload sync_resp = server.sync_request_to_identity(
                client_identity.publicKey,
                ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("sync to id")).build());
            EXPECT_EQ(sync_resp.op_code, OP_PING);
            ObscuraProto::PayloadReader sr(sync_resp);
            EXPECT_EQ(sr.read_param<std::string>(), "sync ok");
            server_done_sync.set_value();

            auto async_future = server.async_request_to_identity(
                client_identity.publicKey,
                ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("async to id")).build());
            if (async_future.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
                ObscuraProto::Payload async_resp = async_future.get();
                EXPECT_EQ(async_resp.op_code, OP_ECHO);
                ObscuraProto::PayloadReader ar(async_resp);
                EXPECT_EQ(ar.read_param<std::string>(), "async ok");
                server_done_async.set_value();
            }
        }).detach();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    client.register_request_handler(OP_PING, [&](ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "sync to id");
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("sync ok")).build();
    });
    client.register_request_handler(OP_ECHO, [&](ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "async to id");
        return ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("async ok")).build();
    });
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).build());
    ASSERT_EQ(server_done_sync.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(server_done_async.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, ConnectionLimitsEnforced) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.rate_limit.enabled = false;
    cfg.connection_limits.max_total = 1;
    cfg.connection_limits.max_per_ip = 5;
    cfg.timeouts.enabled = false;

    ObscuraProto::net::WsServerWrapper server(server_sign_key, cfg);
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client1(client_view_of_server_key, cfg);
    client1.set_client_identity(client_identity);
    std::promise<void> c1_ready;
    client1.set_on_ready_callback([&]() { c1_ready.set_value(); });
    client1.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(c1_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::net::WsClientWrapper client2(client_view_of_server_key, cfg);
    client2.set_client_identity(client_identity);
    std::promise<void> c2_disconnected;
    std::atomic<bool> c2_connected{false};
    client2.set_on_ready_callback([&]() { c2_connected = true; });
    client2.set_on_disconnect_callback([&]() { c2_disconnected.set_value(); });
    client2.connect("ws://localhost:" + std::to_string(port));
    EXPECT_EQ(c2_disconnected.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_FALSE(c2_connected.load());

    client1.disconnect();
    client2.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, PayloadSizeLimitEnforced) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.message_limits.max_decrypted_payload = 20;
    cfg.rate_limit.enabled = false;
    cfg.timeouts.enabled = false;

    ObscuraProto::net::WsServerWrapper server(server_sign_key, cfg);
    std::promise<void> server_got_small;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload) { server_got_small.set_value(); });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key, cfg);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("small")).build());
    ASSERT_EQ(server_got_small.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    EXPECT_THROW(client.send(ObscuraProto::PayloadBuilder(OP_ECHO)
                                 .add_param(std::string("this is a very long payload that exceeds the limit"))
                                 .build()),
                 ObscuraProto::LogicError);

    client.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, DefaultPayloadHandlers) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    constexpr uint16_t OP_UNHANDLED = 0x9002;

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> server_got_default;
    server.set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server.set_default_payload_handler([&](auto hdl, ObscuraProto::Payload payload) {
        EXPECT_EQ(payload.op_code, OP_UNHANDLED);
        server_got_default.set_value();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    client.set_client_identity(client_identity);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_UNHANDLED).build());
    EXPECT_EQ(server_got_default.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, MultipleClientsDataExchange) {
    constexpr int NUM_CLIENTS = 3;
    auto client_identities = std::vector<ObscuraProto::KeyPair>();
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        client_identities.push_back(ObscuraProto::Crypto::generate_sign_keypair());
    }

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::atomic<int> msgs_received{0};
    std::promise<void> all_msgs_received;
    server.set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return true; });
    server.register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "hello from client");
        if (++msgs_received == NUM_CLIENTS) {
            all_msgs_received.set_value();
        }
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::vector<std::unique_ptr<ObscuraProto::net::WsClientWrapper>> clients;
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        auto client = std::make_unique<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
        client->set_client_identity(client_identities[i]);
        std::promise<void> ready;
        client->set_on_ready_callback([&]() { ready.set_value(); });
        client->connect("ws://localhost:" + std::to_string(port));
        ASSERT_EQ(ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
        clients.push_back(std::move(client));
    }

    for (auto& c : clients) {
        c->send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("hello from client")).build());
    }

    EXPECT_EQ(all_msgs_received.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(msgs_received.load(), NUM_CLIENTS);

    for (auto& c : clients) {
        c->disconnect();
    }
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, IdleTimeoutFires) {
    ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
    cfg.timeouts.handshake_ms = 50000;
    cfg.timeouts.idle_ms = 200;
    cfg.timeouts.check_interval_ms = 100;
    cfg.rate_limit.enabled = false;

    ObscuraProto::net::WsServerWrapper server(server_sign_key, cfg);
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key, cfg);
    std::promise<void> client_disconnected;
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.set_on_disconnect_callback([&]() { client_disconnected.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    EXPECT_EQ(client_disconnected.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(ServerEdgeIntegrationTest, AnonDefaultHandler) {
    constexpr uint16_t OP_UNHANDLED = 0x9004;

    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> got_default;
    server.set_anon_default_payload_handler([&](auto hdl, ObscuraProto::Payload payload) {
        EXPECT_EQ(payload.op_code, OP_UNHANDLED);
        got_default.set_value();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.send(ObscuraProto::PayloadBuilder(OP_UNHANDLED).build());
    EXPECT_EQ(got_default.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}
