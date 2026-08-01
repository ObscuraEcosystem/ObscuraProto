#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "../test_helpers.hpp"
#include "obscuraproto/crypto.hpp"
#include "obscuraproto/errors.hpp"
#include "obscuraproto/stream.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

// ============================================================================
// Stage B1: request timeouts.
// Client side: a watchdog thread expires pending promises with TimeoutError.
// Server side: the periodic check_timeouts() timer expires server-initiated
// request promises. Both remove the pending-request record atomically with the
// promise completion, so a late response is ignored instead of throwing
// std::future_error on a double set.
// ============================================================================

namespace {

    constexpr uint16_t OP_NO_RESPONSE = 0x9005;
    constexpr uint16_t OP_SLOW_RESPONSE = 0x9006;

}  // namespace

class RequestTimeoutIntegrationTest : public ::testing::Test {
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

    // Fast server config: periodic timeout checks every 50 ms so server-side
    // request deadlines expire quickly. Rate limiting is off to keep the tests
    // deterministic.
    static ObscuraProto::Config fast_server_config() {
        ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
        cfg.rate_limit.enabled = false;
        cfg.timeouts.check_interval_ms = 50;
        return cfg;
    }

    static ObscuraProto::Config plain_client_config() {
        ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
        cfg.rate_limit.enabled = false;
        return cfg;
    }
};

std::atomic<uint16_t> RequestTimeoutIntegrationTest::port_counter{19950};

// B1: a server that never answers must produce a client-side TimeoutError well
// under one second when a small explicit timeout is passed via the overload.
TEST_F(RequestTimeoutIntegrationTest, ClientRequestTimesOutWhenServerDoesNotRespond) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto start = std::chrono::steady_clock::now();
    // No handler registered for OP_NO_RESPONSE: the request hangs forever.
    auto fut = client->async_request(ObscuraProto::PayloadBuilder(OP_NO_RESPONSE).build(), 300);
    EXPECT_THROW((void) fut.get(), ObscuraProto::TimeoutError);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_LT(elapsed.count(), 1000) << "Timeout must fire in under one second, took " << elapsed.count() << " ms";

    // The connection must remain usable after a timeout.
    server->register_anon_request_handler(OP_PING, [](auto, ObscuraProto::PayloadReader&) -> ObscuraProto::Payload {
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong")).build();
    });
    ObscuraProto::Payload resp =
        client->sync_request(ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("hi")).build(), 2000);
    EXPECT_EQ(resp.op_code, OP_PING);
    ObscuraProto::PayloadReader r(resp);
    EXPECT_EQ(r.read_param<std::string>(), "pong");

    client->disconnect();
    server->stop();
}

// B1: sync_request must also surface the timeout as TimeoutError instead of
// blocking forever on future.get().
TEST_F(RequestTimeoutIntegrationTest, ClientSyncRequestThrowsOnTimeout) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto start = std::chrono::steady_clock::now();
    EXPECT_THROW(client->sync_request(ObscuraProto::PayloadBuilder(OP_NO_RESPONSE).build(), 200),
                 ObscuraProto::TimeoutError);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    EXPECT_LT(elapsed.count(), 1000);

    client->disconnect();
    server->stop();
}

// B1: a prompt response must win the race against the timeout — no TimeoutError.
TEST_F(RequestTimeoutIntegrationTest, ClientRequestCompletesWithinTimeout) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    server->register_anon_request_handler(OP_PING, [](auto, ObscuraProto::PayloadReader&) -> ObscuraProto::Payload {
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong")).build();
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto fut = client->async_request(ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("hi")).build(), 2000);
    ASSERT_EQ(fut.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    ObscuraProto::Payload resp = fut.get();
    EXPECT_EQ(resp.op_code, OP_PING);
    ObscuraProto::PayloadReader r(resp);
    EXPECT_EQ(r.read_param<std::string>(), "pong");

    client->disconnect();
    server->stop();
}

// B1: a response that arrives AFTER the timeout must be ignored — the promise
// was already completed with TimeoutError, so a late set_value must not crash
// or throw std::future_error. The connection stays alive afterwards.
TEST_F(RequestTimeoutIntegrationTest, LateResponseAfterClientTimeoutIsIgnored) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    server->register_anon_request_handler(
        OP_SLOW_RESPONSE, [](auto, ObscuraProto::PayloadReader&) -> ObscuraProto::Payload {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            return ObscuraProto::PayloadBuilder(OP_SLOW_RESPONSE).add_param(std::string("too late")).build();
        });
    server->register_anon_request_handler(OP_PING, [](auto, ObscuraProto::PayloadReader&) -> ObscuraProto::Payload {
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong")).build();
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto fut = client->async_request(ObscuraProto::PayloadBuilder(OP_SLOW_RESPONSE).build(), 100);
    EXPECT_THROW((void) fut.get(), ObscuraProto::TimeoutError);

    // Give the slow server handler time to deliver the late response. It must
    // be dropped silently (no future_error, no crash, no disconnect).
    std::this_thread::sleep_for(std::chrono::milliseconds(700));

    // Follow-up request proves the client and its watchdog are still healthy.
    ObscuraProto::Payload resp =
        client->sync_request(ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("still alive")).build(), 2000);
    EXPECT_EQ(resp.op_code, OP_PING);
    ObscuraProto::PayloadReader r(resp);
    EXPECT_EQ(r.read_param<std::string>(), "pong");

    client->disconnect();
    server->stop();
}

// B1: server-initiated requests must also time out when the client never
// answers. The expiry runs on the server's periodic check_timeouts() timer.
TEST_F(RequestTimeoutIntegrationTest, ServerRequestTimesOutWhenClientDoesNotRespond) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    std::promise<void> got_hdl;
    ObscuraProto::net::WsConnectionHdl client_hdl;
    server->set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool {
        client_hdl = hdl;
        got_hdl.set_value();
        return true;
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    client->set_client_identity(client_identity);
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    // Wait until the server has the client in its session map (synchronizes
    // client_hdl written by the server io thread).
    ASSERT_EQ(got_hdl.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    // The client has NO request handler for OP_NO_RESPONSE: it will not answer.
    auto start = std::chrono::steady_clock::now();
    auto fut = server->async_request(client_hdl, ObscuraProto::PayloadBuilder(OP_NO_RESPONSE).build(), 300);
    auto status = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(status, std::future_status::ready);
    EXPECT_THROW((void) fut.get(), ObscuraProto::TimeoutError);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    EXPECT_LT(elapsed.count(), 1000) << "Server timeout took " << elapsed.count() << " ms";

    client->disconnect();
    server->stop();
}

// B1: server-initiated request with a prompt client answer — no TimeoutError.
TEST_F(RequestTimeoutIntegrationTest, ServerRequestCompletesWithinTimeout) {
    auto client_identity = ObscuraProto::Crypto::generate_sign_keypair();
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    std::promise<void> got_hdl;
    ObscuraProto::net::WsConnectionHdl client_hdl;
    server->set_client_identity_handler([&](auto hdl, ObscuraProto::PublicKey pk) -> bool {
        client_hdl = hdl;
        got_hdl.set_value();
        return true;
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    client->set_client_identity(client_identity);
    client->register_request_handler(OP_PING, [](ObscuraProto::PayloadReader&) -> ObscuraProto::Payload {
        return ObscuraProto::PayloadBuilder(OP_PING).add_param(std::string("pong")).build();
    });
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_EQ(got_hdl.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto fut = server->async_request(client_hdl, ObscuraProto::PayloadBuilder(OP_PING).build(), 2000);
    ASSERT_EQ(fut.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    ObscuraProto::Payload resp = fut.get();
    EXPECT_EQ(resp.op_code, OP_PING);
    ObscuraProto::PayloadReader r(resp);
    EXPECT_EQ(r.read_param<std::string>(), "pong");

    client->disconnect();
    server->stop();
}

// ============================================================================
// Stage B2: Stream::write/end/cancel are noexcept by contract.
// ============================================================================

// Compile-time: the public contract is noexcept.
static_assert(noexcept(std::declval<ObscuraProto::Stream&>().write(std::declval<const ObscuraProto::byte_vector&>())),
              "Stream::write must be noexcept");
static_assert(noexcept(std::declval<ObscuraProto::Stream&>().end()), "Stream::end must be noexcept");
static_assert(noexcept(std::declval<ObscuraProto::Stream&>().cancel()), "Stream::cancel must be noexcept");

// B2: a stream whose owner wrapper has been destroyed must silently drop
// write/end/cancel — no exception may escape (noexcept contract).
TEST_F(RequestTimeoutIntegrationTest, StreamMethodsAreNoexceptAfterOwnerDestroyed) {
    // Simulate an expired owner: the send callback is a silent no-op, exactly
    // what the wrapper installs after its weak_ptr to the owner has expired.
    auto stream = std::make_shared<ObscuraProto::Stream>(42, [](const ObscuraProto::Payload&) {});

    EXPECT_NO_THROW(stream->write(ObscuraProto::byte_vector{'d', 'a', 't', 'a'}));
    EXPECT_NO_THROW(stream->end());
    EXPECT_NO_THROW(stream->cancel());
}

// B2: end-to-end — destroy the real server while the server-side stream handle
// is still alive, then use it. No exceptions, no crash.
TEST_F(RequestTimeoutIntegrationTest, StreamMethodsAfterRealOwnerDestroyed) {
    auto server = std::make_shared<ObscuraProto::net::WsServerWrapper>(server_sign_key, fast_server_config());
    std::shared_ptr<ObscuraProto::Stream> server_stream;
    std::promise<void> got_stream;
    server->register_anon_stream_handler(OP_ECHO, [&](std::shared_ptr<ObscuraProto::Stream> stream) {
        server_stream = stream;
        got_stream.set_value();
    });
    server->run(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto client =
        std::make_shared<ObscuraProto::net::WsClientWrapper>(client_view_of_server_key, plain_client_config());
    std::promise<void> client_ready;
    client->set_on_ready_callback([&]() { client_ready.set_value(); });
    client->connect("ws://localhost:" + std::to_string(port));
    ASSERT_EQ(client_ready.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);

    auto client_stream = client->start_stream(OP_ECHO);
    ASSERT_EQ(got_stream.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
    ASSERT_NE(server_stream, nullptr);

    server->stop();
    server.reset();

    EXPECT_NO_THROW(server_stream->write(ObscuraProto::byte_vector{'x'}));
    EXPECT_NO_THROW(server_stream->end());
    EXPECT_NO_THROW(server_stream->cancel());

    client->disconnect();
}
