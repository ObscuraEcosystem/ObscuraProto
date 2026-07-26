#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

constexpr uint16_t OP_ECHO = 0x8001;

class WsLifecycleTest : public ::testing::Test {
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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
};

std::atomic<uint16_t> WsLifecycleTest::port_counter{19600};

TEST_F(WsLifecycleTest, OnOpenFiresOnClientConnect) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> on_open_fired;
    server.set_on_open_callback([&](auto hdl) { on_open_fired.set_value(); });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));

    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(on_open_fired.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsLifecycleTest, OnCloseFiresOnServerStop) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> on_close_fired;
    server.set_on_close_callback([&](auto hdl) { on_close_fired.set_value(); });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    server.stop();

    EXPECT_EQ(on_close_fired.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
}

TEST_F(WsLifecycleTest, OnOpenAndOnCloseReceiveNonDefaultHdl) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<bool> open_hdl_valid_promise;
    std::promise<bool> close_hdl_valid_promise;
    auto open_hdl_valid_future = open_hdl_valid_promise.get_future();
    auto close_hdl_valid_future = close_hdl_valid_promise.get_future();

    server.set_on_open_callback([&](auto hdl) { open_hdl_valid_promise.set_value(!hdl.expired()); });
    server.set_on_close_callback([&](auto hdl) { close_hdl_valid_promise.set_value(!hdl.expired()); });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    EXPECT_TRUE(open_hdl_valid_future.get());

    server.stop();

    EXPECT_TRUE(close_hdl_valid_future.get());

    client.disconnect();
}

TEST_F(WsLifecycleTest, MultipleConnectionsTriggerOnOpenAndOnClose) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::atomic<int> open_count{0};
    std::atomic<int> close_count{0};
    std::promise<void> all_open;
    std::promise<void> all_closed;
    auto all_open_future = all_open.get_future();
    auto all_closed_future = all_closed.get_future();

    server.set_on_open_callback([&](auto hdl) {
        if (++open_count == 3) {
            all_open.set_value();
        }
    });
    server.set_on_close_callback([&](auto hdl) {
        if (++close_count == 3) {
            all_closed.set_value();
        }
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::vector<std::unique_ptr<ObscuraProto::net::WsClientWrapper>> clients;
    for (int i = 0; i < 3; ++i) {
        auto client = std::make_unique<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key);
        std::promise<void> ready;
        client->set_on_ready_callback([&]() { ready.set_value(); });
        client->connect("ws://localhost:" + std::to_string(port));
        ASSERT_EQ(ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
        clients.push_back(std::move(client));
    }

    EXPECT_EQ(all_open_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(open_count.load(), 3);

    server.stop();

    EXPECT_EQ(all_closed_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(close_count.load(), 3);

    for (auto& c : clients) {
        c->disconnect();
    }
}

TEST_F(WsLifecycleTest, NoCrashWhenCallbacksNotSet) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });
    client.connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}

TEST_F(WsLifecycleTest, OnOpenFiresBeforeHandshakeComplete) {
    ObscuraProto::net::WsServerWrapper server(server_sign_key);
    std::promise<void> on_open_fired;
    std::promise<void> proceed;
    auto proceed_future = proceed.get_future();

    server.set_on_open_callback([&](auto hdl) {
        on_open_fired.set_value();
        proceed_future.wait();
    });
    server.run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);
    std::promise<void> client_ready;
    client.set_on_ready_callback([&]() { client_ready.set_value(); });

    client.connect("ws://localhost:" + std::to_string(port));

    EXPECT_EQ(on_open_fired.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    proceed.set_value();

    EXPECT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    client.disconnect();
    server.stop();
}
