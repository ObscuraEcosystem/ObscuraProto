#ifndef OBSCURAPROTO_STREAM_HPP
#define OBSCURAPROTO_STREAM_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

#include "packet.hpp"

namespace ObscuraProto {

    class Stream : public std::enable_shared_from_this<Stream> {
    public:
        using DataHandler = std::function<void(byte_vector)>;
        using EndHandler = std::function<void()>;
        using CancelHandler = std::function<void()>;
        using SendFn = std::function<void(Payload)>;

        Stream(uint32_t stream_id, SendFn send_fn, std::optional<Payload::OpCode> op_code = std::nullopt)
            : stream_id_(stream_id), send_fn_(std::move(send_fn)), op_code_(op_code) {
        }

        uint32_t get_stream_id() const {
            return stream_id_;
        }

        std::optional<Payload::OpCode> get_op_code() const {
            return op_code_;
        }

        void write(const byte_vector& data);
        void end();
        void cancel();

        void set_data_handler(DataHandler handler) {
            on_data_ = std::move(handler);
        }
        void set_end_handler(EndHandler handler) {
            on_end_ = std::move(handler);
        }
        void set_cancel_handler(CancelHandler handler) {
            on_cancel_ = std::move(handler);
        }

        void dispatch_data(byte_vector data) {
            if (on_data_)
                on_data_(std::move(data));
        }
        void dispatch_end() {
            if (on_end_)
                on_end_();
        }
        void dispatch_cancel() {
            if (on_cancel_)
                on_cancel_();
        }

    private:
        uint32_t stream_id_;
        SendFn send_fn_;
        std::optional<Payload::OpCode> op_code_;

        DataHandler on_data_;
        EndHandler on_end_;
        CancelHandler on_cancel_;
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_STREAM_HPP
