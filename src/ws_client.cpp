#include "obscuraproto/ws_client.hpp"

#include <exception>
#include <iostream>

#include "obscuraproto/errors.hpp"
#include "obscuraproto/handshake_messages.hpp"

namespace ObscuraProto {
    namespace net {

        WsClientWrapper::WsClientWrapper(KeyPair server_sign_key, Config config) : config_(std::move(config)) {
            session_ = std::make_unique<Session>(Role::CLIENT, std::move(server_sign_key), config_.supported_versions);
            client_.init_asio();
            client_.set_open_handler(std::bind(&WsClientWrapper::on_open, this, std::placeholders::_1));
            client_.set_close_handler(std::bind(&WsClientWrapper::on_close, this, std::placeholders::_1));
            client_.set_fail_handler(std::bind(&WsClientWrapper::on_fail, this, std::placeholders::_1));
            client_.set_message_handler(
                std::bind(&WsClientWrapper::on_message, this, std::placeholders::_1, std::placeholders::_2));
            client_.clear_access_channels(websocketpp::log::alevel::all);
            client_.set_close_handshake_timeout(100);

            if (config_.message_limits.enabled && config_.message_limits.max_ws_frame_size > 0) {
                client_.set_max_message_size(config_.message_limits.max_ws_frame_size);
            }
        }

        WsClientWrapper::~WsClientWrapper() {
            disconnect();
        }

        void WsClientWrapper::connect(const std::string& uri) {
            try {
                websocketpp::lib::error_code ec;
                WsClient::connection_ptr con = client_.get_connection(uri, ec);
                if (ec) {
                    throw RuntimeError("Could not create connection: " + ec.message());
                }

                client_.connect(con);

                // If a previous connection thread is still around (a
                // self-disconnect from the io thread deferred its join), wait
                // for it to finish before replacing the handle.
                if (client_thread_ && client_thread_->joinable()) {
                    client_thread_->join();
                }

                client_thread_ = std::make_unique<std::thread>(&WsClientWrapper::run_client, this);

            } catch (const std::exception& e) {
                std::cerr << "Connection failed: " << e.what() << std::endl;
            }
        }

        void WsClientWrapper::set_client_identity(KeyPair identity_kp) {
            client_identity_kp_ = std::move(identity_kp);
        }

        void WsClientWrapper::disconnect() {
            if (!client_thread_) {
                return;
            }

            client_.stop();

            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                for (auto& pair : pending_requests_) {
                    pair.second.set_exception(std::make_exception_ptr(RuntimeError("Client disconnected")));
                }
                pending_requests_.clear();
                request_deadlines_.clear();
            }

            // Wake the watchdog: deadlines were cleared and it must observe the
            // stop flag set by stop_watchdog() below.
            timeout_cv_.notify_all();

            if (is_connected_) {
                try {
                    websocketpp::lib::error_code ec;
                    client_.close(connection_hdl_, websocketpp::close::status::going_away, "", ec);
                    if (ec) {
                    }
                } catch (const websocketpp::exception& e) {
                }
            }

            if (client_thread_->joinable()) {
                if (std::this_thread::get_id() == client_thread_->get_id()) {
                    // Self-join guard: disconnect() can be reached from the io
                    // thread itself (e.g. the on_message catch block after a
                    // user handler threw). Joining our own thread would
                    // deadlock. The io loop has already been stopped above, so
                    // this thread exits by itself right after the current
                    // message handler returns. Keep the std::thread handle: a
                    // later disconnect()/destructor from another thread joins
                    // and releases it.
                    is_connected_ = false;
                    return;
                }
                client_thread_->join();
            }

            client_thread_.reset();
            is_connected_ = false;

            // The watchdog must exit before the destructor finishes: it accesses
            // this instance's members. Safe to join here (never called from the
            // watchdog thread itself).
            stop_watchdog();
        }

        uint32_t WsClientWrapper::resolve_request_timeout(uint32_t explicit_ms) const {
            if (explicit_ms > 0) {
                return explicit_ms;
            }
            if (config_.timeouts.enabled) {
                return config_.timeouts.request_ms;
            }
            return 0;
        }

        void WsClientWrapper::ensure_watchdog() {
            bool expected = false;
            if (!watchdog_started_.compare_exchange_strong(expected, true)) {
                return;
            }
            std::lock_guard<std::mutex> lock(watchdog_mutex_);
            watchdog_stop_ = false;
            watchdog_thread_ = std::make_unique<std::thread>(&WsClientWrapper::watchdog_loop, this);
        }

        void WsClientWrapper::stop_watchdog() {
            std::unique_lock<std::mutex> lock(watchdog_mutex_);
            if (!watchdog_thread_ || !watchdog_thread_->joinable()) {
                watchdog_thread_.reset();
                watchdog_started_ = false;
                return;
            }
            watchdog_stop_ = true;
            timeout_cv_.notify_all();
            lock.unlock();
            watchdog_thread_->join();
            lock.lock();
            watchdog_thread_.reset();
            watchdog_started_ = false;
        }

        void WsClientWrapper::watchdog_loop() {
            using clock = std::chrono::steady_clock;
            std::unique_lock<std::mutex> lock(pending_requests_mutex_);
            while (!watchdog_stop_) {
                auto now = clock::now();
                bool has_deadline = false;
                clock::time_point earliest{};
                for (const auto& [id, deadline] : request_deadlines_) {
                    if (!has_deadline || deadline < earliest) {
                        earliest = deadline;
                        has_deadline = true;
                    }
                }
                if (!has_deadline) {
                    timeout_cv_.wait(lock);
                    continue;
                }
                if (now >= earliest) {
                    // Expire every request whose deadline has passed. The record is
                    // removed atomically with the promise completion, so a late
                    // response handler finds no entry and ignores the response —
                    // std::promise::set_* is never called twice.
                    std::exception_ptr eptr = std::make_exception_ptr(TimeoutError("Request timed out"));
                    auto it = request_deadlines_.begin();
                    while (it != request_deadlines_.end()) {
                        if (it->second <= now) {
                            auto pit = pending_requests_.find(it->first);
                            if (pit != pending_requests_.end()) {
                                pit->second.set_exception(eptr);
                                pending_requests_.erase(pit);
                            }
                            it = request_deadlines_.erase(it);
                        } else {
                            ++it;
                        }
                    }
                    continue;
                }
                timeout_cv_.wait_until(lock, earliest);
            }
        }

        void WsClientWrapper::send(const Payload& payload) {
            if (!is_connected_ || !session_->is_handshake_complete()) {
                throw LogicError("Session not ready for sending data.");
            }

            // Check payload size on send
            if (config_.message_limits.enabled && config_.message_limits.max_decrypted_payload > 0) {
                if (payload.parameters.size() > config_.message_limits.max_decrypted_payload) {
                    throw LogicError("Payload exceeds max_decrypted_payload limit.");
                }
            }

            try {
                EncryptedPacket packet = session_->encrypt_payload(payload);
                client_.send(connection_hdl_, packet.data(), packet.size(), BINDATA_OPCODE);
            } catch (const std::exception& e) {
                std::cerr << "Error sending packet: " << e.what() << std::endl;
            }
        }

        std::future<Payload> WsClientWrapper::async_request(const Payload& payload) {
            return async_request(payload, 0);
        }

        std::future<Payload> WsClientWrapper::async_request(const Payload& payload, uint32_t timeout_ms) {
            if (!is_connected_ || !session_->is_handshake_complete()) {
                throw LogicError("Session not ready for sending requests.");
            }

            uint32_t request_id = next_request_id_++;

            Payload request_payload;
            request_payload.op_code = payload.op_code;

            PayloadBuilder id_builder(0);
            id_builder.add_param(request_id);
            byte_vector id_param = id_builder.build().parameters;

            request_payload.parameters.reserve(id_param.size() + payload.parameters.size());
            request_payload.parameters.insert(request_payload.parameters.end(), id_param.begin(), id_param.end());
            request_payload.parameters.insert(
                request_payload.parameters.end(), payload.parameters.begin(), payload.parameters.end());

            auto promise = std::promise<Payload>();
            auto future = promise.get_future();

            uint32_t effective_timeout = resolve_request_timeout(timeout_ms);

            // The promise is registered BEFORE send(): a response that races
            // back immediately must find its pending record, otherwise it would
            // be dropped as "unknown request". If send() then fails (e.g. the
            // connection closed concurrently after the readiness check), the
            // record is removed and the promise completed with the exception —
            // no orphaned entry can leak (unlimited config) and the returned
            // future resolves instead of hanging.
            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                pending_requests_[request_id] = std::move(promise);
                if (effective_timeout > 0) {
                    request_deadlines_[request_id] =
                        std::chrono::steady_clock::now() + std::chrono::milliseconds(effective_timeout);
                }
            }

            if (effective_timeout > 0) {
                ensure_watchdog();
                timeout_cv_.notify_all();
            }

            try {
                send(request_payload);
            } catch (...) {
                std::exception_ptr eptr = std::current_exception();
                {
                    std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                    auto it = pending_requests_.find(request_id);
                    if (it != pending_requests_.end()) {
                        it->second.set_exception(eptr);
                        pending_requests_.erase(it);
                    }
                    request_deadlines_.erase(request_id);
                }
                std::rethrow_exception(eptr);
            }

            return future;
        }

        void WsClientWrapper::send_response(uint32_t request_id, const Payload& payload) {
            const auto& oc = config_.opcodes;
            PayloadBuilder response_builder(oc.RESPONSE);
            response_builder.add_param(request_id);
            response_builder.add_param(payload.serialize());

            send(response_builder.build());
        }

        std::shared_ptr<Stream> WsClientWrapper::start_stream() {
            uint32_t stream_id = next_outgoing_stream_id_.fetch_add(1) * 2;

            auto stream = std::make_shared<Stream>(
                stream_id, [weak = std::weak_ptr<WsClientWrapper>(weak_from_this())](const Payload& p) {
                    // Silent drop: the owner client is gone (destroyed wrapper).
                    if (auto owner = weak.lock()) {
                        owner->send(p);
                    }
                });

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                active_streams_[stream_id] = stream;
            }

            const auto& oc = config_.opcodes;
            PayloadBuilder builder(oc.STREAM_START);
            builder.add_param(stream_id);
            send(builder.build());

            return stream;
        }

        std::shared_ptr<Stream> WsClientWrapper::start_stream(Payload::OpCode stream_op_code) {
            uint32_t stream_id = next_outgoing_stream_id_.fetch_add(1) * 2;

            auto stream = std::make_shared<Stream>(
                stream_id,
                [weak = std::weak_ptr<WsClientWrapper>(weak_from_this())](const Payload& p) {
                    // Silent drop: the owner client is gone (destroyed wrapper).
                    if (auto owner = weak.lock()) {
                        owner->send(p);
                    }
                },
                stream_op_code);

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                active_streams_[stream_id] = stream;
            }

            const auto& oc = config_.opcodes;
            auto version = session_->get_selected_version();
            PayloadBuilder builder(oc.STREAM_START);
            builder.add_param(stream_id);
            if (version.has_value() && version.value() >= Versions::V1_1) {
                builder.add_param(static_cast<uint16_t>(stream_op_code));
            }
            send(builder.build());

            return stream;
        }

        void WsClientWrapper::register_stream_handler(Payload::OpCode op_code,
                                                      std::function<void(std::shared_ptr<Stream>)> callback) {
            std::lock_guard<std::mutex> lock(stream_handlers_mutex_);
            stream_handlers_[op_code] = std::move(callback);
        }

        void WsClientWrapper::register_incoming_stream_handler(std::function<void(std::shared_ptr<Stream>)> callback) {
            incoming_stream_handler_ = std::move(callback);
        }

        void WsClientWrapper::set_on_ready_callback(OnReadyCallback callback) {
            on_ready_callback_ = std::move(callback);
        }

        void WsClientWrapper::register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            op_code_handlers_[op_code] = std::move(callback);
        }

        void WsClientWrapper::register_request_handler(Payload::OpCode op_code, OnRequestCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            request_handlers_[op_code] = std::move(callback);
        }

        void WsClientWrapper::set_default_payload_handler(OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            default_payload_handler_ = std::move(callback);
        }

        // legacy
        void WsClientWrapper::set_on_payload_callback(OnPayloadCallback callback) {
            set_default_payload_handler(std::move(callback));
        }

        void WsClientWrapper::set_on_disconnect_callback(OnDisconnectCallback callback) {
            on_disconnect_callback_ = std::move(callback);
        }

        void WsClientWrapper::on_open(WsConnectionHdl hdl) {
            connection_hdl_ = hdl;
            is_connected_ = true;

            try {
                if (client_identity_kp_.has_value()) {
                    session_->set_client_identity_key(*client_identity_kp_);
                }
                ClientHello client_hello = session_->client_initiate_handshake();
                byte_vector request = client_hello.serialize();
                client_.send(hdl, request.data(), request.size(), BINDATA_OPCODE);
            } catch (const std::exception& e) {
                std::cerr << "Handshake initiation failed: " << e.what() << std::endl;
                disconnect();
            }
        }

        void WsClientWrapper::on_close(WsConnectionHdl hdl) {
            is_connected_ = false;
            if (on_disconnect_callback_) {
                on_disconnect_callback_();
            }
        }

        void WsClientWrapper::on_fail(WsConnectionHdl hdl) {
            is_connected_ = false;
            if (on_disconnect_callback_) {
                on_disconnect_callback_();
            }
        }

        void WsClientWrapper::on_message(WsConnectionHdl hdl, WsClientMessagePtr msg) {
            if (msg->get_opcode() != BINDATA_OPCODE) {
                return;
            }

            const auto& oc = config_.opcodes;

            try {
                if (!session_->is_handshake_complete()) {
                    byte_vector data(msg->get_payload().begin(), msg->get_payload().end());
                    ServerHello server_hello = ServerHello::deserialize(data);
                    session_->client_finalize_handshake(server_hello);

                    if (session_->is_handshake_complete() && on_ready_callback_) {
                        on_ready_callback_();
                    }
                } else {
                    byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());
                    Payload payload = session_->decrypt_packet(packet);

                    if (config_.message_limits.enabled && config_.message_limits.max_decrypted_payload > 0) {
                        if (payload.parameters.size() > config_.message_limits.max_decrypted_payload) {
                            std::cerr << "Received payload exceeds max_decrypted_payload limit." << std::endl;
                            disconnect();
                            return;
                        }
                    }

                    if (payload.op_code == oc.RESPONSE) {
                        PayloadReader reader(payload);
                        uint32_t request_id = reader.read_param<uint32_t>();
                        byte_vector response_bytes = reader.read_param<byte_vector>();
                        Payload response_payload = Payload::deserialize(response_bytes);

                        {
                            std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                            auto it = pending_requests_.find(request_id);
                            if (it != pending_requests_.end()) {
                                it->second.set_value(std::move(response_payload));
                                pending_requests_.erase(it);
                            } else {
                                std::cerr
                                    << "Received response for unknown or already handled request ID: " << request_id
                                    << std::endl;
                            }
                        }

                    } else if (payload.op_code == oc.STREAM_START || payload.op_code == oc.STREAM_DATA ||
                               payload.op_code == oc.STREAM_END || payload.op_code == oc.STREAM_CANCEL) {
                        PayloadReader reader(payload);
                        uint32_t stream_id = reader.read_param<uint32_t>();

                        if (payload.op_code == oc.STREAM_START) {
                            std::optional<Payload::OpCode> stream_op_code = std::nullopt;
                            if (reader.has_more()) {
                                stream_op_code = reader.read_param<uint16_t>();
                            }

                            auto stream = std::make_shared<Stream>(
                                stream_id,
                                [weak = std::weak_ptr<WsClientWrapper>(weak_from_this())](const Payload& p) {
                                    // Silent drop: the owner client is gone (destroyed wrapper).
                                    if (auto owner = weak.lock()) {
                                        owner->send(p);
                                    }
                                },
                                stream_op_code);
                            {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                active_streams_[stream_id] = stream;
                            }

                            bool handled = false;
                            std::function<void(std::shared_ptr<Stream>)> stream_handler;
                            if (stream_op_code.has_value()) {
                                std::lock_guard<std::mutex> lock(stream_handlers_mutex_);
                                auto it = stream_handlers_.find(*stream_op_code);
                                if (it != stream_handlers_.end()) {
                                    stream_handler = it->second;
                                    handled = true;
                                }
                            }
                            if (stream_handler) {
                                stream_handler(std::move(stream));
                            } else if (!handled && incoming_stream_handler_) {
                                incoming_stream_handler_(std::move(stream));
                            }
                        } else if (payload.op_code == oc.STREAM_DATA) {
                            byte_vector data = reader.read_param<byte_vector>();
                            std::shared_ptr<Stream> stream;
                            {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto it = active_streams_.find(stream_id);
                                if (it != active_streams_.end()) {
                                    stream = it->second;
                                }
                            }
                            // Dispatch outside streams_mutex_: user handlers may call start_stream().
                            if (stream) {
                                stream->dispatch_data(std::move(data));
                            }
                        } else if (payload.op_code == oc.STREAM_END) {
                            std::shared_ptr<Stream> stream;
                            {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto it = active_streams_.find(stream_id);
                                if (it != active_streams_.end()) {
                                    stream = it->second;
                                }
                            }
                            if (stream) {
                                stream->dispatch_end();
                            }
                        } else if (payload.op_code == oc.STREAM_CANCEL) {
                            std::shared_ptr<Stream> stream;
                            {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                auto it = active_streams_.find(stream_id);
                                if (it != active_streams_.end()) {
                                    stream = it->second;
                                    active_streams_.erase(it);
                                }
                            }
                            if (stream) {
                                stream->dispatch_cancel();
                            }
                        }

                    } else {
                        bool handled = false;
                        OnRequestCallback request_handler;
                        OnPayloadCallback op_handler;
                        OnPayloadCallback default_handler;

                        {
                            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
                            auto req_it = request_handlers_.find(payload.op_code);
                            if (req_it != request_handlers_.end()) {
                                request_handler = req_it->second;
                                handled = true;
                            } else {
                                auto op_it = op_code_handlers_.find(payload.op_code);
                                if (op_it != op_code_handlers_.end()) {
                                    op_handler = op_it->second;
                                    handled = true;
                                } else {
                                    default_handler = default_payload_handler_;
                                }
                            }
                        }

                        if (request_handler) {
                            PayloadReader reader(payload);
                            uint32_t request_id = reader.read_param<uint32_t>();
                            Payload response_payload = request_handler(reader);
                            send_response(request_id, response_payload);
                        } else if (op_handler) {
                            op_handler(std::move(payload));
                        } else if (default_handler) {
                            default_handler(std::move(payload));
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Message processing failed: " << e.what() << std::endl;
                disconnect();
            }
        }

        void WsClientWrapper::run_client() {
            try {
                client_.run();
            } catch (const std::exception& e) {
                std::cerr << "Client thread exception: " << e.what() << std::endl;
            }
        }

        Payload WsClientWrapper::sync_request(const Payload& payload) {
            return sync_request(payload, 0);
        }

        Payload WsClientWrapper::sync_request(const Payload& payload, uint32_t timeout_ms) {
            auto future_result = this->async_request(payload, timeout_ms);
            uint32_t effective_timeout = resolve_request_timeout(timeout_ms);
            if (effective_timeout == 0) {
                return future_result.get();
            }
            if (future_result.wait_for(std::chrono::milliseconds(effective_timeout)) == std::future_status::timeout) {
                // The watchdog completes the promise with TimeoutError shortly
                // afterwards; throwing here unblocks the caller immediately.
                throw TimeoutError("Request timed out");
            }
            return future_result.get();
        }

    }  // namespace net
}  // namespace ObscuraProto
