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

class FullCycleIntegrationTest : public ::testing::Test {
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

    static ObscuraProto::Config server_config() {
        ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
        cfg.supported_versions = {ObscuraProto::Versions::V1_1, ObscuraProto::Versions::V1_0};
        cfg.rate_limit.enabled = false;
        cfg.timeouts.enabled = false;
        return cfg;
    }

    static ObscuraProto::Config client_config(std::vector<ObscuraProto::Version> versions) {
        ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
        cfg.supported_versions = std::move(versions);
        cfg.rate_limit.enabled = false;
        cfg.timeouts.enabled = false;
        return cfg;
    }
};

std::atomic<uint16_t> FullCycleIntegrationTest::port_counter{19800};

TEST_F(FullCycleIntegrationTest, FullCycleV1_1) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, server_config());
    std::promise<void> anon_op_done;
    std::promise<void> anon_req_done;
    std::promise<void> anon_stream_done;
    std::promise<void> anon_stream_data_done;
    std::promise<void> anon_default_done;
    std::promise<void> auth_op_done;
    std::promise<void> auth_req_done;
    std::promise<void> auth_stream_done;
    std::promise<void> auth_stream_data_done;
    std::promise<void> srv_init_req_done;
    std::promise<void> identity_msg_done;
    std::promise<void> srv_stream_done;
    std::promise<void> srv_stream_data_done;

    constexpr uint16_t OP_UNHANDLED = 0x9003;
    constexpr uint16_t OP_SRV_INIT = 0x8004;

    server->register_anon_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        EXPECT_EQ(r.read_param<std::string>(), "anon_op");
        anon_op_done.set_value();
    });
    server->register_anon_request_handler(
        OP_PING, [&](auto hdl, ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
            std::string msg = r.read_param<std::string>();
            EXPECT_EQ(msg, "anon_req");
            anon_req_done.set_value();
            return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong")).build();
        });
    server->register_anon_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        anon_stream_done.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string m(data.begin(), data.end());
            EXPECT_EQ(m, "anon_stream");
            anon_stream_data_done.set_value();
        });
    });
    server->set_anon_default_payload_handler([&](auto hdl, ObscuraProto::Payload payload) {
        EXPECT_EQ(payload.op_code, OP_UNHANDLED);
        anon_default_done.set_value();
    });

    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        EXPECT_EQ(r.read_param<std::string>(), "auth_op");
        auth_op_done.set_value();
    });
    server->register_request_handler(OP_PING, [&](auto hdl, ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "auth_req");
        auth_req_done.set_value();
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("auth_pong")).build();
    });
    server->register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        auth_stream_done.set_value();
        stream->set_data_handler([stream, &auth_stream_data_done](const ObscuraProto::byte_vector& data) {
            std::string m(data.begin(), data.end());
            EXPECT_EQ(m, "auth_stream");
            auth_stream_data_done.set_value();
            stream->write(ObscuraProto::byte_vector{'s', 't', 'r', 'e', 'a', 'm', '_', 'o', 'k'});
        });
    });
    server->register_op_handler(OP_SRV_INIT, [&](auto hdl, ObscuraProto::Payload) {
        std::thread([&, hdl]() {
            auto fut = server->async_request(
                hdl, ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("srv_req")).build());
            if (fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
                auto resp = fut.get();
                ObscuraProto::PayloadReader r(resp);
                EXPECT_EQ(r.read_param<std::string>(), "srv_resp");
                srv_init_req_done.set_value();
            }
        }).detach();
        server->send_to_identity(client_identity.publicKey,
                                 ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("to_identity")).build());
        auto srv_stream = server->start_stream(hdl, OP_ECHO);
        srv_stream->write(ObscuraProto::byte_vector{'s', 'r', 'v', '_', 's', 't', 'r', 'e', 'a', 'm'});
    });

    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Anonymous client
    auto anon_client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, server_config());
    std::promise<void> anon_ready;
    anon_client->set_on_ready_callback([&]() { anon_ready.set_value(); });
    anon_client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(anon_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    anon_client->send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("anon_op")).build());
    ASSERT_EQ(anon_op_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload anon_resp =
        anon_client->sync_request(ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("anon_req")).build());
    EXPECT_EQ(anon_resp.op_code, OP_PING);
    ObscuraProto::PayloadReader anon_r(anon_resp);
    EXPECT_EQ(anon_r.read_param<std::string>(), "pong");
    ASSERT_EQ(anon_req_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto anon_stream = anon_client->start_stream(OP_ECHO);
    ASSERT_EQ(anon_stream_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    anon_stream->write(ObscuraProto::byte_vector{'a', 'n', 'o', 'n', '_', 's', 't', 'r', 'e', 'a', 'm'});
    ASSERT_EQ(anon_stream_data_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    anon_client->send(ObscuraProto::PayloadBuilder(OP_UNHANDLED).build());
    ASSERT_EQ(anon_default_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    // Authenticated client
    auto auth_client = std::make_shared<ObscuraProto::net::WsClientWrapper>(
        client_view_of_server_key, client_config({ObscuraProto::Versions::V1_1, ObscuraProto::Versions::V1_0}));
    auth_client->set_client_identity(client_identity);
    auth_client->register_request_handler(OP_PING, [&](ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "srv_req");
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("srv_resp")).build();
    });
    auth_client->register_op_handler(OP_ECHO, [&](ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "to_identity");
        identity_msg_done.set_value();
    });
    auth_client->register_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        EXPECT_TRUE(stream->get_op_code().has_value());
        EXPECT_EQ(stream->get_op_code().value(), OP_ECHO);
        srv_stream_done.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string m(data.begin(), data.end());
            EXPECT_EQ(m, "srv_stream");
            srv_stream_data_done.set_value();
        });
    });
    std::promise<void> auth_ready;
    auth_client->set_on_ready_callback([&]() { auth_ready.set_value(); });
    auth_client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(auth_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auth_client->send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("auth_op")).build());
    ASSERT_EQ(auth_op_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload auth_resp =
        auth_client->sync_request(ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("auth_req")).build());
    EXPECT_EQ(auth_resp.op_code, OP_PING);
    ObscuraProto::PayloadReader auth_r(auth_resp);
    EXPECT_EQ(auth_r.read_param<std::string>(), "auth_pong");
    ASSERT_EQ(auth_req_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto auth_stream = auth_client->start_stream(OP_ECHO);
    ASSERT_EQ(auth_stream_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    auth_stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string m(data.begin(), data.end());
        EXPECT_EQ(m, "stream_ok");
    });
    auth_stream->write(ObscuraProto::byte_vector{'a', 'u', 't', 'h', '_', 's', 't', 'r', 'e', 'a', 'm'});
    ASSERT_EQ(auth_stream_data_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auth_client->send(ObscuraProto::PayloadBuilder(OP_SRV_INIT).build());
    ASSERT_EQ(srv_init_req_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(identity_msg_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(srv_stream_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(srv_stream_data_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    anon_client->disconnect();
    auth_client->disconnect();
    server->stop();
}

TEST_F(FullCycleIntegrationTest, FullCycleV1_0) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();

    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, server_config());
    std::promise<void> anon_op_done;
    std::promise<void> anon_req_done;
    std::promise<void> anon_stream_done;
    std::promise<void> anon_stream_data_done;
    std::promise<void> auth_op_done;
    std::promise<void> auth_req_done;
    std::promise<void> auth_stream_done;
    std::promise<void> auth_stream_data_done;
    std::promise<void> srv_init_req_done;
    std::promise<void> identity_msg_done;
    std::promise<void> srv_stream_done;
    std::promise<void> srv_stream_data_done;

    constexpr uint16_t OP_SRV_INIT = 0x8004;

    server->register_anon_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        EXPECT_EQ(r.read_param<std::string>(), "v1.0_anon_op");
        anon_op_done.set_value();
    });
    server->register_anon_request_handler(
        OP_PING, [&](auto hdl, ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
            std::string msg = r.read_param<std::string>();
            EXPECT_EQ(msg, "v1.0_anon_req");
            anon_req_done.set_value();
            return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong")).build();
        });
    std::atomic<int> v1_0_stream_seq{0};
    server->register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        int seq = v1_0_stream_seq++;
        if (seq == 0) {
            EXPECT_FALSE(stream->get_op_code().has_value());
            anon_stream_done.set_value();
            stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
                std::string m(data.begin(), data.end());
                EXPECT_EQ(m, "v1.0_anon_stream");
                anon_stream_data_done.set_value();
            });
        } else {
            EXPECT_FALSE(stream->get_op_code().has_value());
            auth_stream_done.set_value();
            stream->set_data_handler([stream, &auth_stream_data_done](const ObscuraProto::byte_vector& data) {
                std::string m(data.begin(), data.end());
                EXPECT_EQ(m, "v1.0_auth_stream");
                auth_stream_data_done.set_value();
                stream->write(ObscuraProto::byte_vector{'o', 'k'});
            });
        }
    });

    server->set_client_identity_handler(
        [&](auto hdl, ObscuraProto::PublicKey pk) -> bool { return pk.data == client_identity.publicKey.data; });
    server->register_op_handler(OP_ECHO, [&](auto hdl, ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        EXPECT_EQ(r.read_param<std::string>(), "v1.0_auth_op");
        auth_op_done.set_value();
    });
    server->register_request_handler(OP_PING, [&](auto hdl, ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "v1.0_auth_req");
        auth_req_done.set_value();
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("auth_pong")).build();
    });
    server->register_op_handler(OP_SRV_INIT, [&](auto hdl, ObscuraProto::Payload) {
        std::thread([&, hdl]() {
            auto fut = server->async_request(
                hdl, ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("srv_req")).build());
            if (fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
                auto resp = fut.get();
                ObscuraProto::PayloadReader r(resp);
                EXPECT_EQ(r.read_param<std::string>(), "v1.0_srv_resp");
                srv_init_req_done.set_value();
            }
        }).detach();
        server->send_to_identity(client_identity.publicKey,
                                 ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("v1.0_to_id")).build());
        auto srv_stream = server->start_stream(hdl);
        srv_stream->write(ObscuraProto::byte_vector{'v', '1', '.', '0', '_', 's', 'r', 'v'});
    });

    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Anonymous client (V1_0 only so streams don't include op_code)
    ObscuraProto::Config anon_cfg = server_config();
    anon_cfg.supported_versions = {ObscuraProto::Versions::V1_0};
    auto anon_client = std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, anon_cfg);
    std::promise<void> anon_ready;
    anon_client->set_on_ready_callback([&]() { anon_ready.set_value(); });
    anon_client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(anon_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    anon_client->send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("v1.0_anon_op")).build());
    ASSERT_EQ(anon_op_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload anon_resp = anon_client->sync_request(
        ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("v1.0_anon_req")).build());
    EXPECT_EQ(anon_resp.op_code, OP_PING);
    ObscuraProto::PayloadReader anon_r(anon_resp);
    EXPECT_EQ(anon_r.read_param<std::string>(), "pong");
    ASSERT_EQ(anon_req_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto anon_stream = anon_client->start_stream();
    ASSERT_EQ(anon_stream_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    anon_stream->write(
        ObscuraProto::byte_vector{'v', '1', '.', '0', '_', 'a', 'n', 'o', 'n', '_', 's', 't', 'r', 'e', 'a', 'm'});
    ASSERT_EQ(anon_stream_data_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    // Authenticated client
    auto auth_client = std::make_shared<ObscuraProto::net::WsClientWrapper>(
        client_view_of_server_key, client_config({ObscuraProto::Versions::V1_0}));
    auth_client->set_client_identity(client_identity);
    auth_client->register_request_handler(OP_PING, [&](ObscuraProto::PayloadReader& r) -> ObscuraProto::Payload {
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "srv_req");
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("v1.0_srv_resp")).build();
    });
    auth_client->register_op_handler(OP_ECHO, [&](ObscuraProto::Payload payload) {
        ObscuraProto::PayloadReader r(payload);
        std::string msg = r.read_param<std::string>();
        EXPECT_EQ(msg, "v1.0_to_id");
        identity_msg_done.set_value();
    });
    auth_client->register_incoming_stream_handler([&](std::shared_ptr<ObscuraProto::Stream> stream) {
        srv_stream_done.set_value();
        stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
            std::string m(data.begin(), data.end());
            EXPECT_EQ(m, "v1.0_srv");
            srv_stream_data_done.set_value();
        });
    });
    std::promise<void> auth_ready;
    auth_client->set_on_ready_callback([&]() { auth_ready.set_value(); });
    auth_client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(auth_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auth_client->send(ObscuraProto::PayloadBuilder(OP_ECHO).add_param(std::string("v1.0_auth_op")).build());
    ASSERT_EQ(auth_op_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    ObscuraProto::Payload auth_resp = auth_client->sync_request(
        ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("v1.0_auth_req")).build());
    EXPECT_EQ(auth_resp.op_code, OP_PING);
    ObscuraProto::PayloadReader auth_r(auth_resp);
    EXPECT_EQ(auth_r.read_param<std::string>(), "auth_pong");
    ASSERT_EQ(auth_req_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto auth_stream = auth_client->start_stream();
    ASSERT_EQ(auth_stream_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    auth_stream->set_data_handler([&](const ObscuraProto::byte_vector& data) {
        std::string m(data.begin(), data.end());
        EXPECT_EQ(m, "ok");
    });
    auth_stream->write(
        ObscuraProto::byte_vector{'v', '1', '.', '0', '_', 'a', 'u', 't', 'h', '_', 's', 't', 'r', 'e', 'a', 'm'});
    ASSERT_EQ(auth_stream_data_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auth_client->send(ObscuraProto::PayloadBuilder(OP_SRV_INIT).build());
    ASSERT_EQ(srv_init_req_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(identity_msg_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(srv_stream_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(srv_stream_data_done.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    anon_client->disconnect();
    auth_client->disconnect();
    server->stop();
}
