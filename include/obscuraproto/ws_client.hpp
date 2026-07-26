#ifndef OBSCURAPROTO_WS_CLIENT_HPP
#define OBSCURAPROTO_WS_CLIENT_HPP

#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <thread>

#include "config.hpp"
#include "session.hpp"
#include "stream.hpp"
#include "ws_common.hpp"

namespace ObscuraProto {
    namespace net {

        class WsClientWrapper {
        public:
            using OnReadyCallback = std::function<void()>;
            using OnPayloadCallback = std::function<void(Payload)>;
            using OnRequestCallback = std::function<Payload(PayloadReader&)>;
            using OnDisconnectCallback = std::function<void()>;

            WsClientWrapper(KeyPair server_sign_key, Config config = Config::with_defaults());
            ~WsClientWrapper();

            /**
             * @brief Sets the client's Ed25519 identity keypair for authentication.
             * @param identity_kp The client's Ed25519 keypair.
             */
            void set_client_identity(KeyPair identity_kp);

            void connect(const std::string& uri);
            void disconnect();
            void send(const Payload& payload);

            /**
             * @brief Sends a payload and returns a future for the response.
             * @param payload The payload to send. The op_code should indicate a request.
             * @return A future that will contain the response payload.
             */
            std::future<Payload> async_request(const Payload& payload);

            /**
             * @brief Sends a payload and returns a response.
             * @param payload The payload to send. The op_code should indicate a request.
             * @return A response payload.
             */
            Payload sync_request(const Payload& payload);

            /**
             * @brief Sends a response to a specific server-initiated request.
             * @param request_id The ID of the request being responded to.
             * @param payload The response payload.
             */
            void send_response(uint32_t request_id, const Payload& payload);

            void set_on_ready_callback(OnReadyCallback callback);

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
             * @brief DEPRECATED: Sets the default payload handler. Use set_default_payload_handler for clarity.
             */
            void set_on_payload_callback(OnPayloadCallback callback);
            void set_on_disconnect_callback(OnDisconnectCallback callback);

            /**
             * @brief Starts a new outgoing stream.
             * @return A shared pointer to the new Stream object.
             */
            std::shared_ptr<Stream> start_stream();

            /**
             * @brief Starts a new outgoing stream with a specific op_code.
             * @param stream_op_code The op_code for the stream.
             * @return A shared pointer to the new Stream object.
             */
            std::shared_ptr<Stream> start_stream(Payload::OpCode stream_op_code);

            /**
             * @brief Registers a handler for incoming streams initiated by the server.
             * @param callback The function to call when a new stream is received.
             */
            void register_incoming_stream_handler(std::function<void(std::shared_ptr<Stream>)> callback);

            /**
             * @brief Registers a handler for incoming streams with a specific op_code.
             * @param op_code The op_code of streams to handle.
             * @param callback The function to call when a matching stream is received.
             */
            void register_stream_handler(Payload::OpCode op_code,
                                         std::function<void(std::shared_ptr<Stream>)> callback);

        private:
            void on_open(WsConnectionHdl hdl);
            void on_close(WsConnectionHdl hdl);
            void on_fail(WsConnectionHdl hdl);
            void on_message(WsConnectionHdl hdl, WsClientMessagePtr msg);
            void run_client();

            WsClient client_;
            Config config_;
            std::unique_ptr<Session> session_;
            std::optional<KeyPair> client_identity_kp_;
            WsConnectionHdl connection_hdl_;
            std::unique_ptr<std::thread> client_thread_;
            bool is_connected_ = false;

            OnReadyCallback on_ready_callback_;
            OnDisconnectCallback on_disconnect_callback_;

            // For payload handling
            std::mutex op_handlers_mutex_;
            std::map<Payload::OpCode, OnPayloadCallback> op_code_handlers_;
            std::map<Payload::OpCode, OnRequestCallback> request_handlers_;
            OnPayloadCallback default_payload_handler_;

            // For request-response mechanism
            std::mutex pending_requests_mutex_;
            std::map<uint32_t, std::promise<Payload>> pending_requests_;
            std::atomic<uint32_t> next_request_id_{0};

            // For streaming
            std::mutex streams_mutex_;
            std::map<uint32_t, std::shared_ptr<Stream>> active_streams_;
            std::function<void(std::shared_ptr<Stream>)> incoming_stream_handler_;
            uint32_t next_outgoing_stream_id_ = 0;

            // For op_code-routed streams
            std::mutex stream_handlers_mutex_;
            std::map<Payload::OpCode, std::function<void(std::shared_ptr<Stream>)>> stream_handlers_;
        };

    }  // namespace net
}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_WS_CLIENT_HPP
