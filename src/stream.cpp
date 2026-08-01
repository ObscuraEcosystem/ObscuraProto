#include "obscuraproto/stream.hpp"

#include <iostream>

namespace ObscuraProto {

    // send_fn_ is a void(Payload) callback installed by the owner wrapper
    // (WsClientWrapper / WsServerWrapper). The wrapper captures a weak_ptr to itself,
    // so when the owner has been destroyed the call below is a silent no-op:
    // no exception, no undefined behavior, data is simply dropped.
    //
    // These methods are noexcept by contract (B2): any internal failure
    // (allocation, encoding, transport) is logged and swallowed so a stale
    // stream handle can never propagate an exception into user code or across
    // the FFI boundary.
    void Stream::write(const byte_vector& data) noexcept {
        try {
            PayloadBuilder builder(OpCode::STREAM_DATA);
            builder.add_param(stream_id_);
            builder.add_param(data);
            send_fn_(builder.build());
        } catch (const std::exception& e) {
            std::cerr << "Stream::write failed: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Stream::write failed: unknown error" << std::endl;
        }
    }

    void Stream::end() noexcept {
        try {
            PayloadBuilder builder(OpCode::STREAM_END);
            builder.add_param(stream_id_);
            send_fn_(builder.build());
        } catch (const std::exception& e) {
            std::cerr << "Stream::end failed: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Stream::end failed: unknown error" << std::endl;
        }
    }

    void Stream::cancel() noexcept {
        try {
            PayloadBuilder builder(OpCode::STREAM_CANCEL);
            builder.add_param(stream_id_);
            send_fn_(builder.build());
        } catch (const std::exception& e) {
            std::cerr << "Stream::cancel failed: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Stream::cancel failed: unknown error" << std::endl;
        }
    }

}  // namespace ObscuraProto
