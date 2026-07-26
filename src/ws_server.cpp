#include "obscuraproto/ws_server.hpp"

#include <iostream>

#include "obscuraproto/errors.hpp"
#include "obscuraproto/handshake_messages.hpp"

namespace ObscuraProto {
    namespace net {

        WsServerWrapper::WsServerWrapper(KeyPair server_sign_key, Config config)
            : config_(std::move(config)),
              rate_limiter_(config_.rate_limit),
              server_sign_key_(std::move(server_sign_key)) {
            server_.init_asio();
            server_.set_reuse_addr(true);
            server_.set_open_handler(std::bind(&WsServerWrapper::on_open, this, std::placeholders::_1));
            server_.set_close_handler(std::bind(&WsServerWrapper::on_close, this, std::placeholders::_1));
            server_.set_message_handler(
                std::bind(&WsServerWrapper::on_message, this, std::placeholders::_1, std::placeholders::_2));
            server_.clear_access_channels(websocketpp::log::alevel::all);
            server_.set_close_handshake_timeout(100);

            if (config_.message_limits.enabled && config_.message_limits.max_ws_frame_size > 0) {
                server_.set_max_message_size(config_.message_limits.max_ws_frame_size);
            }
        }

        WsServerWrapper::~WsServerWrapper() {
            stop();
        }

        void WsServerWrapper::run(uint16_t port) {
            server_thread_ = std::make_unique<std::thread>([this, port]() {
                try {
                    server_.listen(port);
                    server_.start_accept();
                    if (config_.timeouts.enabled && config_.timeouts.handshake_ms > 0 && config_.timeouts.idle_ms > 0) {
                        schedule_timeout_check();
                    }
                    server_.run();
                } catch (const std::exception& e) {
                    std::cerr << "Server thread exception: " << e.what() << std::endl;
                }
            });
        }

        void WsServerWrapper::stop() {
            stopping_ = true;
            if (server_.is_listening()) {
                server_.stop_listening();
            }

            if (timeout_timer_) {
                timeout_timer_->cancel();
                timeout_timer_.reset();
            }

            // Fulfill any pending request promises with an exception
            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                for (auto& [conn_hdl, requests] : pending_requests_) {
                    for (auto& [id, promise] : requests) {
                        promise.set_exception(std::make_exception_ptr(RuntimeError("Server is stopping")));
                    }
                }
                pending_requests_.clear();
            }

            // Iterate over all authenticated connections and close them
            for (auto const& [hdl, state] : sessions_) {
                try {
                    server_.close(hdl, websocketpp::close::status::going_away, "Server shutdown");
                } catch (const websocketpp::exception& e) {
                    // Ignore exceptions on close
                }
            }
            sessions_.clear();

            // Iterate over all anonymous connections and close them
            for (auto const& [hdl, state] : anon_sessions_) {
                try {
                    server_.close(hdl, websocketpp::close::status::going_away, "Server shutdown");
                } catch (const websocketpp::exception& e) {
                    // Ignore exceptions on close
                }
            }
            anon_sessions_.clear();

            {
                std::lock_guard<std::mutex> lock(identity_map_mutex_);
                identity_to_hdl_.clear();
                hdl_to_identity_.clear();
            }

            if (server_thread_ && server_thread_->joinable()) {
                server_thread_->join();
            }
        }

        std::string WsServerWrapper::get_remote_ip(WsConnectionHdl hdl) {
            try {
                auto con = server_.get_con_from_hdl(hdl);
                return con->get_remote_endpoint();
            } catch (...) {
                return "unknown";
            }
        }

        void WsServerWrapper::send(WsConnectionHdl hdl, const Payload& payload) {
            Session* session = nullptr;
            auto it = sessions_.find(hdl);
            if (it != sessions_.end() && it->second.session.is_handshake_complete()) {
                session = &it->second.session;
            } else {
                auto anon_it = anon_sessions_.find(hdl);
                if (anon_it != anon_sessions_.end() && anon_it->second.session.is_handshake_complete()) {
                    session = &anon_it->second.session;
                }
            }
            if (!session) {
                throw LogicError("Session not ready for sending data.");
            }

            try {
                EncryptedPacket packet = session->encrypt_payload(payload);
                server_.send(hdl, packet.data(), packet.size(), BINDATA_OPCODE);
            } catch (const std::exception& e) {
                std::cerr << "Error sending packet: " << e.what() << std::endl;
            }
        }

        void WsServerWrapper::send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload) {
            const auto& oc = config_.opcodes;
            PayloadBuilder response_builder(oc.RESPONSE);
            response_builder.add_param(request_id);
            response_builder.add_param(payload.serialize());

            send(hdl, response_builder.build());
        }

        std::future<Payload> WsServerWrapper::async_request(WsConnectionHdl hdl, const Payload& payload) {
            Session* session = nullptr;
            auto it = sessions_.find(hdl);
            if (it != sessions_.end() && it->second.session.is_handshake_complete()) {
                session = &it->second.session;
            } else {
                auto anon_it = anon_sessions_.find(hdl);
                if (anon_it != anon_sessions_.end() && anon_it->second.session.is_handshake_complete()) {
                    session = &anon_it->second.session;
                }
            }
            if (!session) {
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

            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                pending_requests_[hdl][request_id] = std::move(promise);
            }

            send(hdl, request_payload);

            return future;
        }

        std::shared_ptr<Stream> WsServerWrapper::start_stream(WsConnectionHdl hdl) {
            uint32_t stream_id = next_outgoing_stream_id_ * 2 + 1;
            next_outgoing_stream_id_++;

            auto stream = std::make_shared<Stream>(stream_id, [this, hdl](const Payload& p) { send(hdl, p); });

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                per_connection_streams_[hdl][stream_id] = stream;
            }

            const auto& oc = config_.opcodes;
            PayloadBuilder builder(oc.STREAM_START);
            builder.add_param(stream_id);
            send(hdl, builder.build());

            return stream;
        }

        std::shared_ptr<Stream> WsServerWrapper::start_stream(WsConnectionHdl hdl, Payload::OpCode stream_op_code) {
            uint32_t stream_id = next_outgoing_stream_id_ * 2 + 1;
            next_outgoing_stream_id_++;

            auto stream =
                std::make_shared<Stream>(stream_id, [this, hdl](const Payload& p) { send(hdl, p); }, stream_op_code);

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                per_connection_streams_[hdl][stream_id] = stream;
            }

            const auto& oc = config_.opcodes;
            auto it = sessions_.find(hdl);
            if (it != sessions_.end()) {
                auto version = it->second.session.get_selected_version();
                PayloadBuilder builder(oc.STREAM_START);
                builder.add_param(stream_id);
                if (version.has_value() && version.value() >= Versions::V1_1) {
                    builder.add_param(static_cast<uint16_t>(stream_op_code));
                }
                send(hdl, builder.build());
            } else {
                auto anon_it = anon_sessions_.find(hdl);
                if (anon_it != anon_sessions_.end()) {
                    auto version = anon_it->second.session.get_selected_version();
                    PayloadBuilder builder(oc.STREAM_START);
                    builder.add_param(stream_id);
                    if (version.has_value() && version.value() >= Versions::V1_1) {
                        builder.add_param(static_cast<uint16_t>(stream_op_code));
                    }
                    send(hdl, builder.build());
                } else {
                    throw LogicError("Session not found for this connection.");
                }
            }

            return stream;
        }

        void WsServerWrapper::register_stream_handler(Payload::OpCode op_code,
                                                      std::function<void(std::shared_ptr<Stream>)> callback) {
            std::lock_guard<std::mutex> lock(stream_handlers_mutex_);
            stream_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::register_anon_stream_handler(Payload::OpCode op_code,
                                                           std::function<void(std::shared_ptr<Stream>)> callback) {
            std::lock_guard<std::mutex> lock(anon_stream_handlers_mutex_);
            anon_stream_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::register_incoming_stream_handler(std::function<void(std::shared_ptr<Stream>)> callback) {
            incoming_stream_handler_ = std::move(callback);
        }

        void WsServerWrapper::register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            op_code_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::register_request_handler(Payload::OpCode op_code, OnRequestCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            request_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::set_default_payload_handler(OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(op_handlers_mutex_);
            default_payload_handler_ = std::move(callback);
        }

        void WsServerWrapper::set_on_open_callback(OnOpenCallback callback) {
            on_open_callback_ = std::move(callback);
        }

        void WsServerWrapper::set_on_close_callback(OnCloseCallback callback) {
            on_close_callback_ = std::move(callback);
        }

        // legacy
        void WsServerWrapper::set_on_payload_callback(OnPayloadCallback callback) {
            set_default_payload_handler(std::move(callback));
        }

        void WsServerWrapper::on_open(WsConnectionHdl hdl) {
            std::string ip = get_remote_ip(hdl);

            // Rate limiting: check connection rate per IP
            if (config_.rate_limit.enabled) {
                if (!rate_limiter_.check_connection_rate(ip)) {
                    server_.close(hdl, websocketpp::close::status::policy_violation, "Connection rate limit exceeded");
                    return;
                }
                rate_limiter_.record_connection(ip);
            }

            // Connection limits: check max per IP
            if (config_.connection_limits.enabled) {
                if (config_.connection_limits.max_total > 0 &&
                    rate_limiter_.active_total() >= config_.connection_limits.max_total) {
                    server_.close(hdl, websocketpp::close::status::policy_violation, "Max connections reached");
                    return;
                }
            }

            // Track handshake open time
            if (config_.timeouts.enabled && config_.timeouts.handshake_ms > 0) {
                std::lock_guard<std::mutex> lock(handshake_time_mutex_);
                handshake_open_time_[hdl] = now_ms();
            }

            // Note: we wait for the ClientHello to create a session.
            // Remote IP is recorded per-connection in on_close cleanup.

            // Notify the callback after the connection is set up
            if (on_open_callback_) {
                on_open_callback_(hdl);
            }
        }

        void WsServerWrapper::on_close(WsConnectionHdl hdl) {
            // Notify the callback before cleanup (hdl is still valid)
            if (on_close_callback_) {
                on_close_callback_(hdl);
            }

            auto auth_it = sessions_.find(hdl);
            if (auth_it != sessions_.end()) {
                rate_limiter_.unregister_connection(auth_it->second.rate_limiter_id, auth_it->second.remote_ip);
                sessions_.erase(auth_it);
            }

            auto anon_it = anon_sessions_.find(hdl);
            if (anon_it != anon_sessions_.end()) {
                rate_limiter_.unregister_connection(anon_it->second.rate_limiter_id, anon_it->second.remote_ip);
                anon_sessions_.erase(anon_it);
            }

            {
                std::lock_guard<std::mutex> lock(identity_map_mutex_);
                auto id_it = hdl_to_identity_.find(hdl);
                if (id_it != hdl_to_identity_.end()) {
                    identity_to_hdl_.erase(id_it->second);
                    hdl_to_identity_.erase(id_it);
                }
            }

            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                per_connection_streams_.erase(hdl);
            }

            {
                std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                auto conn_it = pending_requests_.find(hdl);
                if (conn_it != pending_requests_.end()) {
                    for (auto& [id, promise] : conn_it->second) {
                        promise.set_exception(std::make_exception_ptr(RuntimeError("Client disconnected")));
                    }
                    pending_requests_.erase(conn_it);
                }
            }

            {
                std::lock_guard<std::mutex> lock(handshake_time_mutex_);
                handshake_open_time_.erase(hdl);
            }
        }

        // --- Timeout checking ---

        void WsServerWrapper::schedule_timeout_check() {
            if (stopping_ || !config_.timeouts.enabled) {
                return;
            }
            uint32_t interval = config_.timeouts.check_interval_ms;
            if (interval == 0) {
                interval = 5000;
            }
            timeout_timer_ = server_.set_timer(interval, [this](const websocketpp::lib::error_code& ec) {
                if (ec || stopping_) {
                    return;
                }
                check_timeouts();
                schedule_timeout_check();
            });
        }

        void WsServerWrapper::check_timeouts() {
            int64_t now = now_ms();

            // Idle timeout check
            if (config_.timeouts.idle_ms > 0) {
                for (auto& [hdl, state] : sessions_) {
                    if (state.last_activity_ms > 0 &&
                        (now - state.last_activity_ms) > static_cast<int64_t>(config_.timeouts.idle_ms)) {
                        try {
                            server_.close(hdl, websocketpp::close::status::policy_violation, "Idle timeout");
                        } catch (...) {
                        }
                    }
                }
                for (auto& [hdl, state] : anon_sessions_) {
                    if (state.last_activity_ms > 0 &&
                        (now - state.last_activity_ms) > static_cast<int64_t>(config_.timeouts.idle_ms)) {
                        try {
                            server_.close(hdl, websocketpp::close::status::policy_violation, "Idle timeout");
                        } catch (...) {
                        }
                    }
                }
            }

            // Handshake timeout check
            if (config_.timeouts.handshake_ms > 0) {
                std::lock_guard<std::mutex> lock(handshake_time_mutex_);
                auto it = handshake_open_time_.begin();
                while (it != handshake_open_time_.end()) {
                    if ((now - it->second) > static_cast<int64_t>(config_.timeouts.handshake_ms)) {
                        auto hdl = it->first;
                        try {
                            server_.close(hdl, websocketpp::close::status::policy_violation, "Handshake timeout");
                        } catch (...) {
                        }
                        it = handshake_open_time_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Clean up rate limiter stale entries
            rate_limiter_.cleanup();
        }

        // --- Anonymous Session Methods ---

        void WsServerWrapper::send_anonymous(WsConnectionHdl hdl, const Payload& payload) {
            auto it = anon_sessions_.find(hdl);
            if (it == anon_sessions_.end() || !it->second.session.is_handshake_complete()) {
                throw LogicError("Anonymous session not ready for sending data.");
            }

            try {
                EncryptedPacket packet = it->second.session.encrypt_payload(payload);
                server_.send(hdl, packet.data(), packet.size(), BINDATA_OPCODE);
            } catch (const std::exception& e) {
                std::cerr << "Error sending packet to anonymous session: " << e.what() << std::endl;
            }
        }

        void WsServerWrapper::register_anon_op_handler(Payload::OpCode op_code, OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(anon_op_handlers_mutex_);
            anon_op_code_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::register_anon_request_handler(Payload::OpCode op_code, OnRequestCallback callback) {
            std::lock_guard<std::mutex> lock(anon_op_handlers_mutex_);
            anon_request_handlers_[op_code] = std::move(callback);
        }

        void WsServerWrapper::set_anon_default_payload_handler(OnPayloadCallback callback) {
            std::lock_guard<std::mutex> lock(anon_op_handlers_mutex_);
            anon_default_payload_handler_ = std::move(callback);
        }

        // --- Client Identity Methods ---

        void WsServerWrapper::set_client_identity_handler(IdentityHandler callback) {
            client_identity_handler_ = std::move(callback);
        }

        PublicKey WsServerWrapper::get_client_identity(WsConnectionHdl hdl) {
            auto it = sessions_.find(hdl);
            if (it == sessions_.end()) {
                throw LogicError("Session not found for this connection.");
            }
            auto identity = it->second.session.get_peer_identity();
            if (!identity.has_value()) {
                throw LogicError("Session has no peer identity.");
            }
            return *identity;
        }

        void WsServerWrapper::send_to_identity(const PublicKey& identity_pk, const Payload& payload) {
            std::lock_guard<std::mutex> lock(identity_map_mutex_);
            auto it = identity_to_hdl_.find(identity_pk);
            if (it == identity_to_hdl_.end()) {
                throw LogicError("Identity is not connected.");
            }
            send(it->second, payload);
        }

        std::future<Payload> WsServerWrapper::async_request_to_identity(const PublicKey& identity_pk,
                                                                        const Payload& payload) {
            std::lock_guard<std::mutex> lock(identity_map_mutex_);
            auto it = identity_to_hdl_.find(identity_pk);
            if (it == identity_to_hdl_.end()) {
                throw LogicError("Identity is not connected.");
            }
            return async_request(it->second, payload);
        }

        Payload WsServerWrapper::sync_request_to_identity(const PublicKey& identity_pk, const Payload& payload) {
            auto future_result = this->async_request_to_identity(identity_pk, payload);
            Payload result = future_result.get();
            return result;
        }

        // --- Message Dispatch ---

        static void dispatch_payload(
            WsConnectionHdl hdl,
            Payload& payload,
            WsServerWrapper& server,
            const std::map<Payload::OpCode, WsServerWrapper::OnRequestCallback>& request_handlers,
            const std::map<Payload::OpCode, WsServerWrapper::OnPayloadCallback>& op_code_handlers,
            const WsServerWrapper::OnPayloadCallback& default_handler,
            std::mutex& handlers_mutex,
            std::function<void(WsConnectionHdl, uint32_t, const Payload&)> send_response_fn) {
            bool handled = false;
            WsServerWrapper::OnRequestCallback request_handler;
            WsServerWrapper::OnPayloadCallback op_handler;
            WsServerWrapper::OnPayloadCallback default_h;

            {
                std::lock_guard<std::mutex> lock(handlers_mutex);
                auto req_it = request_handlers.find(payload.op_code);
                if (req_it != request_handlers.end()) {
                    request_handler = req_it->second;
                    handled = true;
                } else {
                    auto op_it = op_code_handlers.find(payload.op_code);
                    if (op_it != op_code_handlers.end()) {
                        op_handler = op_it->second;
                        handled = true;
                    } else {
                        default_h = default_handler;
                    }
                }
            }

            if (request_handler) {
                PayloadReader reader(payload);
                uint32_t request_id = reader.read_param<uint32_t>();
                Payload response_payload = request_handler(hdl, reader);
                send_response_fn(hdl, request_id, response_payload);
            } else if (op_handler) {
                op_handler(hdl, std::move(payload));
            } else if (default_h) {
                default_h(hdl, std::move(payload));
            }
        }

        void WsServerWrapper::on_message(WsConnectionHdl hdl, WsMessagePtr msg) {
            if (msg->get_opcode() != BINDATA_OPCODE) {
                return;
            }

            const auto& oc = config_.opcodes;

            // Check if this is an existing authenticated session
            auto auth_it = sessions_.find(hdl);
            if (auth_it != sessions_.end()) {
                Session& session = auth_it->second.session;
                if (!session.is_handshake_complete()) {
                    return;
                }

                // Rate limiting: check message rate per connection
                if (config_.rate_limit.enabled && !rate_limiter_.check_message_rate(auth_it->second.rate_limiter_id)) {
                    server_.close(hdl, websocketpp::close::status::policy_violation, "Message rate limit exceeded");
                    return;
                }

                try {
                    byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());

                    // Payload size limit check (before decryption — encrypted size)
                    if (config_.message_limits.enabled && config_.message_limits.max_decrypted_payload > 0) {
                        // Rough estimate: encrypted payload shouldn't be much larger than decrypted
                        // We check decrypted size after decryption below
                    }

                    Payload payload = session.decrypt_packet(packet);

                    // Payload size limit check (decrypted)
                    if (config_.message_limits.enabled && config_.message_limits.max_decrypted_payload > 0) {
                        if (payload.parameters.size() > config_.message_limits.max_decrypted_payload) {
                            server_.close(hdl, websocketpp::close::status::policy_violation, "Payload too large");
                            return;
                        }
                    }

                    // Record message for rate limiter
                    if (config_.rate_limit.enabled) {
                        rate_limiter_.record_message(auth_it->second.rate_limiter_id);
                    }

                    // Update last activity for idle timeout
                    auth_it->second.last_activity_ms = now_ms();

                    if (payload.op_code == oc.RESPONSE) {
                        PayloadReader reader(payload);
                        uint32_t request_id = reader.read_param<uint32_t>();
                        byte_vector response_bytes = reader.read_param<byte_vector>();
                        Payload response_payload = Payload::deserialize(response_bytes);

                        {
                            std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                            auto conn_it = pending_requests_.find(hdl);
                            if (conn_it != pending_requests_.end()) {
                                auto req_it = conn_it->second.find(request_id);
                                if (req_it != conn_it->second.end()) {
                                    req_it->second.set_value(std::move(response_payload));
                                    conn_it->second.erase(req_it);
                                } else {
                                    std::cerr << "[SERVER] Received response for unknown request ID: " << request_id
                                              << std::endl;
                                }
                            } else {
                                std::cerr << "[SERVER] Received response for unknown connection" << std::endl;
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
                                stream_id, [this, hdl](const Payload& p) { send(hdl, p); }, stream_op_code);
                            {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                per_connection_streams_[hdl][stream_id] = stream;
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
                            std::lock_guard<std::mutex> lock(streams_mutex_);
                            auto conn_it = per_connection_streams_.find(hdl);
                            if (conn_it != per_connection_streams_.end()) {
                                auto str_it = conn_it->second.find(stream_id);
                                if (str_it != conn_it->second.end()) {
                                    str_it->second->dispatch_data(std::move(data));
                                }
                            }
                        } else if (payload.op_code == oc.STREAM_END) {
                            std::lock_guard<std::mutex> lock(streams_mutex_);
                            auto conn_it = per_connection_streams_.find(hdl);
                            if (conn_it != per_connection_streams_.end()) {
                                auto str_it = conn_it->second.find(stream_id);
                                if (str_it != conn_it->second.end()) {
                                    str_it->second->dispatch_end();
                                }
                            }
                        } else if (payload.op_code == oc.STREAM_CANCEL) {
                            std::lock_guard<std::mutex> lock(streams_mutex_);
                            auto conn_it = per_connection_streams_.find(hdl);
                            if (conn_it != per_connection_streams_.end()) {
                                auto str_it = conn_it->second.find(stream_id);
                                if (str_it != conn_it->second.end()) {
                                    str_it->second->dispatch_cancel();
                                    conn_it->second.erase(str_it);
                                }
                            }
                        }

                    } else {
                        dispatch_payload(
                            hdl,
                            payload,
                            *this,
                            request_handlers_,
                            op_code_handlers_,
                            default_payload_handler_,
                            op_handlers_mutex_,
                            [this](WsConnectionHdl h, uint32_t rid, const Payload& p) { send_response(h, rid, p); });
                    }

                } catch (const std::exception& e) {
                    std::cerr << "Decryption failed for authenticated session: " << e.what() << std::endl;
                }
                return;
            }

            // Check if this is an existing anonymous session
            auto anon_it = anon_sessions_.find(hdl);
            if (anon_it != anon_sessions_.end()) {
                Session& session = anon_it->second.session;
                if (!session.is_handshake_complete()) {
                    return;
                }

                // Rate limiting: check message rate per connection
                if (config_.rate_limit.enabled && !rate_limiter_.check_message_rate(anon_it->second.rate_limiter_id)) {
                    server_.close(hdl, websocketpp::close::status::policy_violation, "Message rate limit exceeded");
                    return;
                }

                try {
                    byte_vector packet(msg->get_payload().begin(), msg->get_payload().end());
                    Payload payload = session.decrypt_packet(packet);

                    // Payload size limit check (decrypted)
                    if (config_.message_limits.enabled && config_.message_limits.max_decrypted_payload > 0) {
                        if (payload.parameters.size() > config_.message_limits.max_decrypted_payload) {
                            server_.close(hdl, websocketpp::close::status::policy_violation, "Payload too large");
                            return;
                        }
                    }

                    // Record message for rate limiter
                    if (config_.rate_limit.enabled) {
                        rate_limiter_.record_message(anon_it->second.rate_limiter_id);
                    }

                    // Update last activity
                    anon_it->second.last_activity_ms = now_ms();

                    if (payload.op_code == oc.RESPONSE) {
                        PayloadReader reader(payload);
                        uint32_t request_id = reader.read_param<uint32_t>();
                        byte_vector response_bytes = reader.read_param<byte_vector>();
                        Payload response_payload = Payload::deserialize(response_bytes);

                        {
                            std::lock_guard<std::mutex> lock(pending_requests_mutex_);
                            auto conn_it = pending_requests_.find(hdl);
                            if (conn_it != pending_requests_.end()) {
                                auto req_it = conn_it->second.find(request_id);
                                if (req_it != conn_it->second.end()) {
                                    req_it->second.set_value(std::move(response_payload));
                                    conn_it->second.erase(req_it);
                                } else {
                                    std::cerr
                                        << "[SERVER] Received anonymous response for unknown request ID: " << request_id
                                        << std::endl;
                                }
                            } else {
                                std::cerr << "[SERVER] Received anonymous response for unknown connection" << std::endl;
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
                                stream_id, [this, hdl](const Payload& p) { send_anonymous(hdl, p); }, stream_op_code);
                            {
                                std::lock_guard<std::mutex> lock(streams_mutex_);
                                per_connection_streams_[hdl][stream_id] = stream;
                            }

                            bool handled = false;
                            std::function<void(std::shared_ptr<Stream>)> stream_handler;
                            if (stream_op_code.has_value()) {
                                std::lock_guard<std::mutex> lock(anon_stream_handlers_mutex_);
                                auto it = anon_stream_handlers_.find(*stream_op_code);
                                if (it != anon_stream_handlers_.end()) {
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
                            std::lock_guard<std::mutex> lock(streams_mutex_);
                            auto conn_it = per_connection_streams_.find(hdl);
                            if (conn_it != per_connection_streams_.end()) {
                                auto str_it = conn_it->second.find(stream_id);
                                if (str_it != conn_it->second.end()) {
                                    str_it->second->dispatch_data(std::move(data));
                                }
                            }
                        } else if (payload.op_code == oc.STREAM_END) {
                            std::lock_guard<std::mutex> lock(streams_mutex_);
                            auto conn_it = per_connection_streams_.find(hdl);
                            if (conn_it != per_connection_streams_.end()) {
                                auto str_it = conn_it->second.find(stream_id);
                                if (str_it != conn_it->second.end()) {
                                    str_it->second->dispatch_end();
                                }
                            }
                        } else if (payload.op_code == oc.STREAM_CANCEL) {
                            std::lock_guard<std::mutex> lock(streams_mutex_);
                            auto conn_it = per_connection_streams_.find(hdl);
                            if (conn_it != per_connection_streams_.end()) {
                                auto str_it = conn_it->second.find(stream_id);
                                if (str_it != conn_it->second.end()) {
                                    str_it->second->dispatch_cancel();
                                    conn_it->second.erase(str_it);
                                }
                            }
                        }

                    } else {
                        dispatch_payload(hdl,
                                         payload,
                                         *this,
                                         anon_request_handlers_,
                                         anon_op_code_handlers_,
                                         anon_default_payload_handler_,
                                         anon_op_handlers_mutex_,
                                         [this](WsConnectionHdl h, uint32_t rid, const Payload& p) {
                                             const auto& oc = config_.opcodes;
                                             PayloadBuilder response_builder(oc.RESPONSE);
                                             response_builder.add_param(rid);
                                             response_builder.add_param(p.serialize());
                                             send_anonymous(h, response_builder.build());
                                         });
                    }

                } catch (const std::exception& e) {
                    std::cerr << "Decryption failed for anonymous session: " << e.what() << std::endl;
                }
                return;
            }

            // --- New connection, expect ClientHello ---
            try {
                // Rate limiting: check handshake rate per IP
                std::string ip = get_remote_ip(hdl);
                if (config_.rate_limit.enabled && !rate_limiter_.check_handshake_rate(ip)) {
                    server_.close(hdl, websocketpp::close::status::policy_violation, "Handshake rate limit exceeded");
                    return;
                }

                byte_vector data(msg->get_payload().begin(), msg->get_payload().end());
                ClientHello client_hello = ClientHello::deserialize(data);

                bool is_identified = client_hello.has_client_identity;

                Session temp_session(Role::SERVER, server_sign_key_, config_.supported_versions);
                ServerHello server_hello = temp_session.server_respond_to_handshake(client_hello);
                byte_vector response = server_hello.serialize();
                server_.send(hdl, response.data(), response.size(), BINDATA_OPCODE);

                // Record successful handshake
                if (config_.rate_limit.enabled) {
                    rate_limiter_.record_handshake(ip);
                }

                if (is_identified && temp_session.has_peer_identity()) {
                    PublicKey client_pk = *temp_session.get_peer_identity();

                    bool accepted = true;
                    if (client_identity_handler_) {
                        accepted = client_identity_handler_(hdl, client_pk);
                    }

                    if (accepted) {
                        uint64_t conn_id = rate_limiter_.register_connection(ip);
                        auto emplace_result =
                            sessions_.emplace(hdl, ConnectionState(std::move(temp_session), conn_id, ip, now_ms()));
                        {
                            std::lock_guard<std::mutex> lock(identity_map_mutex_);
                            identity_to_hdl_[client_pk] = hdl;
                            hdl_to_identity_[hdl] = client_pk;
                        }
                    } else {
                        server_.close(hdl, websocketpp::close::status::policy_violation, "Identity rejected");
                    }
                } else {
                    uint64_t conn_id = rate_limiter_.register_connection(ip);
                    anon_sessions_.emplace(hdl, ConnectionState(std::move(temp_session), conn_id, ip, now_ms()));
                }

                // Clear handshake timeout tracking since handshake completed
                {
                    std::lock_guard<std::mutex> lock(handshake_time_mutex_);
                    handshake_open_time_.erase(hdl);
                }

            } catch (const std::exception& e) {
                std::cerr << "Handshake failed: " << e.what() << std::endl;
                server_.close(hdl, websocketpp::close::status::policy_violation, "Handshake error");
            }
        }

        Payload WsServerWrapper::sync_request(WsConnectionHdl hdl, const Payload& payload) {
            auto future_result = this->async_request(hdl, payload);
            Payload result = future_result.get();
            return result;
        }

    }  // namespace net
}  // namespace ObscuraProto
