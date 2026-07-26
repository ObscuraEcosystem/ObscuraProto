#ifndef OBSCURAPROTO_WS_SERVER_HPP
#define OBSCURAPROTO_WS_SERVER_HPP

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "config.hpp"
#include "rate_limiter.hpp"
#include "session.hpp"
#include "stream.hpp"
#include "ws_common.hpp"

namespace ObscuraProto {
    namespace net {

        class WsServerWrapper {
        public:
            using OnPayloadCallback = std::function<void(WsConnectionHdl, Payload)>;
            using OnRequestCallback = std::function<Payload(WsConnectionHdl, PayloadReader&)>;
            using IdentityHandler = std::function<bool(WsConnectionHdl, PublicKey)>;

            // Callbacks for connection lifecycle events
            using OnOpenCallback = std::function<void(WsConnectionHdl)>;
            using OnCloseCallback = std::function<void(WsConnectionHdl)>;

            WsServerWrapper(KeyPair server_sign_key, Config config = Config::with_defaults());
            ~WsServerWrapper();

            void run(uint16_t port);
            void stop();
            void send(WsConnectionHdl hdl, const Payload& payload);

            /**
             * @brief Sends a response to a specific request.
             * @param hdl The connection handle of the client.
             * @param request_id The ID of the request being responded to.
             * @param payload The response payload.
             */
            void send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload);

            /**
             * @brief Sends a request to a client and returns a future for the response.
             * @param hdl The connection handle of the client.
             * @param payload The payload to send as a request.
             * @return A future that will contain the response payload.
             */
            std::future<Payload> async_request(WsConnectionHdl hdl, const Payload& payload);

            /**
             * @brief Sends a request to a client and returns a response.
             * @param hdl The connection handle of the client.
             * @param payload The payload to send as a request.
             * @return A response payload.
             */
            Payload sync_request(WsConnectionHdl hdl, const Payload& payload);

            /**
             * @brief Registers a handler for a specific operation code.
             * @param op_code The operation code to handle.
             * @param callback The function to call when a payload with this op_code is received.
             */
            void register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback);

            /**
             * @brief Registers a simplified handler for a request-response flow.
             * @param op_code The operation code of the request to handle.
             * @param callback The function to call. It receives a reader for the request parameters
             *                 and should return a payload for the response.
             */
            void register_request_handler(Payload::OpCode op_code, OnRequestCallback callback);

            /**
             * @brief Sets a default handler for any operation code that doesn't have a specific handler registered.
             * @param callback The function to call.
             */
            void set_default_payload_handler(OnPayloadCallback callback);

            /**
             * @brief Registers a callback called when a new WebSocket connection is opened.
             * @param callback The function to call with the connection handle.
             */
            void set_on_open_callback(OnOpenCallback callback);

            /**
             * @brief Registers a callback called when a WebSocket connection is closed.
             * @param callback The function to call with the connection handle.
             */
            void set_on_close_callback(OnCloseCallback callback);

            /**
             * @brief DEPRECATED: Sets the default payload handler. Use set_default_payload_handler for clarity.
             */
            void set_on_payload_callback(OnPayloadCallback callback);

            /**
             * @brief Starts a new outgoing stream to a specific client.
             * @param hdl The connection handle of the client.
             * @return A shared pointer to the new Stream object.
             */
            std::shared_ptr<Stream> start_stream(WsConnectionHdl hdl);

            /**
             * @brief Starts a new outgoing stream to a specific client with a specific op_code.
             * @param hdl The connection handle of the client.
             * @param stream_op_code The op_code for the stream.
             * @return A shared pointer to the new Stream object.
             */
            std::shared_ptr<Stream> start_stream(WsConnectionHdl hdl, Payload::OpCode stream_op_code);

            /**
             * @brief Registers a handler for incoming streams initiated by a client.
             * @param callback The function to call when a new stream is received.
             */
            void register_incoming_stream_handler(std::function<void(std::shared_ptr<Stream>)> callback);

            /**
             * @brief Registers a handler for incoming authenticated streams with a specific op_code.
             * @param op_code The op_code of streams to handle.
             * @param callback The function to call when a matching stream is received.
             */
            void register_stream_handler(Payload::OpCode op_code,
                                         std::function<void(std::shared_ptr<Stream>)> callback);

            /**
             * @brief Registers a handler for incoming anonymous streams with a specific op_code.
             * @param op_code The op_code of streams to handle.
             * @param callback The function to call when a matching stream is received.
             */
            void register_anon_stream_handler(Payload::OpCode op_code,
                                              std::function<void(std::shared_ptr<Stream>)> callback);

            // --- Anonymous Sessions ---

            /**
             * @brief Sends a payload to an anonymous session.
             * @param hdl The connection handle of the anonymous client.
             * @param payload The payload to send.
             */
            void send_anonymous(WsConnectionHdl hdl, const Payload& payload);

            /**
             * @brief Registers a handler for a specific operation code on anonymous sessions.
             * @param op_code The operation code to handle.
             * @param callback The function to call when a payload with this op_code is received from an anonymous
             * client.
             */
            void register_anon_op_handler(Payload::OpCode op_code, OnPayloadCallback callback);

            /**
             * @brief Registers a simplified request-response handler for anonymous sessions.
             * @param op_code The operation code of the request to handle.
             * @param callback The function to call. It receives a reader for the request parameters
             *                 and should return a payload for the response.
             */
            void register_anon_request_handler(Payload::OpCode op_code, OnRequestCallback callback);

            /**
             * @brief Sets a default handler for anonymous sessions.
             * @param callback The function to call for any unhandled opcode from an anonymous client.
             */
            void set_anon_default_payload_handler(OnPayloadCallback callback);

            // --- Client Identity ---

            /**
             * @brief Sets a handler that is called when a client authenticates with an identity key.
             * @param callback The function to call. It receives the connection handle and the client's
             *                 Ed25519 public key. Return true to accept the connection, false to reject it.
             */
            void set_client_identity_handler(IdentityHandler callback);

            /**
             * @brief Gets the verified identity public key for an authenticated session.
             * @param hdl The connection handle of the authenticated client.
             * @return The client's Ed25519 public key.
             * @throws ObscuraProto::LogicError if the session has no peer identity.
             */
            PublicKey get_client_identity(WsConnectionHdl hdl);

            /**
             * @brief Sends a payload to a specific client identified by their public key.
             * @param identity_pk The client's Ed25519 public key.
             * @param payload The payload to send.
             * @throws ObscuraProto::LogicError if the identity is not connected.
             */
            void send_to_identity(const PublicKey& identity_pk, const Payload& payload);

            /**
             * @brief Sends a request to a specific client identified by their public key.
             * @param identity_pk The client's Ed25519 public key.
             * @param payload The payload to send as a request.
             * @return A future that will contain the response payload.
             * @throws ObscuraProto::LogicError if the identity is not connected.
             */
            std::future<Payload> async_request_to_identity(const PublicKey& identity_pk, const Payload& payload);

            /**
             * @brief Sends a synchronous request to a specific client identified by their public key.
             * @param identity_pk The client's Ed25519 public key.
             * @param payload The payload to send as a request.
             * @return A response payload.
             * @throws ObscuraProto::LogicError if the identity is not connected.
             */
            Payload sync_request_to_identity(const PublicKey& identity_pk, const Payload& payload);

        private:
            struct ConnectionState {
                ConnectionState(Session&& sess, uint64_t rl_id, std::string ip, int64_t activity)
                    : session(std::move(sess)),
                      rate_limiter_id(rl_id),
                      remote_ip(std::move(ip)),
                      last_activity_ms(activity) {
                }

                Session session;
                uint64_t rate_limiter_id = 0;
                std::string remote_ip;
                int64_t last_activity_ms = 0;
            };

            void on_open(WsConnectionHdl hdl);
            void on_close(WsConnectionHdl hdl);
            void on_message(WsConnectionHdl hdl, WsMessagePtr msg);

            std::string get_remote_ip(WsConnectionHdl hdl);

            void schedule_timeout_check();
            void check_timeouts();

            WsServer server_;
            Config config_;
            RateLimiter rate_limiter_;
            KeyPair server_sign_key_;

            std::map<WsConnectionHdl, ConnectionState, std::owner_less<WsConnectionHdl>> sessions_;
            std::map<WsConnectionHdl, ConnectionState, std::owner_less<WsConnectionHdl>> anon_sessions_;

            // Timestamp when a connection was opened (for handshake timeout)
            std::map<WsConnectionHdl, int64_t, std::owner_less<WsConnectionHdl>> handshake_open_time_;
            std::mutex handshake_time_mutex_;

            std::mutex op_handlers_mutex_;
            std::map<Payload::OpCode, OnPayloadCallback> op_code_handlers_;
            std::map<Payload::OpCode, OnRequestCallback> request_handlers_;
            OnPayloadCallback default_payload_handler_;

            // Anonymous handlers
            std::mutex anon_op_handlers_mutex_;
            std::map<Payload::OpCode, OnPayloadCallback> anon_op_code_handlers_;
            std::map<Payload::OpCode, OnRequestCallback> anon_request_handlers_;
            OnPayloadCallback anon_default_payload_handler_;

            std::unique_ptr<std::thread> server_thread_;

            // For request-response mechanism (server-to-client)
            std::mutex pending_requests_mutex_;
            std::map<WsConnectionHdl, std::map<uint32_t, std::promise<Payload>>, std::owner_less<WsConnectionHdl>>
                pending_requests_;
            std::atomic<uint32_t> next_request_id_{0};

            // For streaming
            std::mutex streams_mutex_;
            std::map<WsConnectionHdl, std::map<uint32_t, std::shared_ptr<Stream>>, std::owner_less<WsConnectionHdl>>
                per_connection_streams_;
            std::function<void(std::shared_ptr<Stream>)> incoming_stream_handler_;
            uint32_t next_outgoing_stream_id_ = 0;

            // For op_code-routed streams (authenticated)
            std::mutex stream_handlers_mutex_;
            std::map<Payload::OpCode, std::function<void(std::shared_ptr<Stream>)>> stream_handlers_;

            // For op_code-routed streams (anonymous)
            std::mutex anon_stream_handlers_mutex_;
            std::map<Payload::OpCode, std::function<void(std::shared_ptr<Stream>)>> anon_stream_handlers_;

            // Client identity
            IdentityHandler client_identity_handler_;
            std::mutex identity_map_mutex_;
            std::map<PublicKey, WsConnectionHdl> identity_to_hdl_;
            std::map<WsConnectionHdl, PublicKey, std::owner_less<WsConnectionHdl>> hdl_to_identity_;

            // Callbacks for connection lifecycle
            OnOpenCallback on_open_callback_;
            OnCloseCallback on_close_callback_;

            // Periodic timeout check timer
            std::shared_ptr<asio::steady_timer> timeout_timer_;
            std::atomic<bool> stopping_{false};

            using clock = std::chrono::steady_clock;

            int64_t now_ms() const {
                return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now().time_since_epoch()).count();
            }
        };

    }  // namespace net
}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_WS_SERVER_HPP
