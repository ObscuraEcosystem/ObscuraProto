#ifndef OBSCURAPROTO_SECURE_BUFFER_HPP
#define OBSCURAPROTO_SECURE_BUFFER_HPP

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace ObscuraProto {

    class SecureBuffer {
    public:
        SecureBuffer() = default;

        explicit SecureBuffer(size_t size) {
            if (size > 0) {
                allocate(size);
            }
        }

        ~SecureBuffer() {
            clear();
        }

        SecureBuffer(const SecureBuffer& other) {
            if (other.size_ > 0) {
                allocate(other.size_);
                std::memcpy(data_, other.data_, size_);
            }
        }

        SecureBuffer& operator=(const SecureBuffer& other) {
            if (this != &other) {
                clear();
                if (other.size_ > 0) {
                    allocate(other.size_);
                    std::memcpy(data_, other.data_, size_);
                }
            }
            return *this;
        }

        SecureBuffer(SecureBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
            other.data_ = nullptr;
            other.size_ = 0;
        }

        SecureBuffer& operator=(SecureBuffer&& other) noexcept {
            if (this != &other) {
                clear();
                data_ = other.data_;
                size_ = other.size_;
                other.data_ = nullptr;
                other.size_ = 0;
            }
            return *this;
        }

        void resize(size_t new_size) {
            if (new_size == size_) {
                return;
            }
            SecureBuffer tmp(new_size);
            size_t copy_size = (new_size < size_) ? new_size : size_;
            if (copy_size > 0 && tmp.data_ && data_) {
                std::memcpy(tmp.data_, data_, copy_size);
            }
            std::swap(data_, tmp.data_);
            std::swap(size_, tmp.size_);
        }

        uint8_t* data() {
            return data_;
        }
        const uint8_t* data() const {
            return data_;
        }

        size_t size() const {
            return size_;
        }
        bool empty() const {
            return size_ == 0;
        }

        uint8_t& operator[](size_t i) {
            return data_[i];
        }
        const uint8_t& operator[](size_t i) const {
            return data_[i];
        }

        uint8_t* begin() {
            return data_;
        }
        uint8_t* end() {
            return data_ + size_;
        }
        const uint8_t* begin() const {
            return data_;
        }
        const uint8_t* end() const {
            return data_ + size_;
        }

        void assign(const uint8_t* src, size_t n) {
            clear();
            if (n > 0) {
                allocate(n);
                std::memcpy(data_, src, n);
            }
        }

        void clear() {
            if (data_) {
                sodium_memzero(data_, size_);
                sodium_free(data_);
                data_ = nullptr;
                size_ = 0;
            }
        }

    private:
        void allocate(size_t size) {
            // sodium_malloc does not zero the memory it returns: zero every
            // fresh allocation so callers cannot observe heap contents through
            // bytes they have not written (the size ctor, copy/assign and
            // resize() growth all expose the raw buffer).
            data_ = static_cast<uint8_t*>(sodium_malloc(size));
            if (!data_) {
                throw std::bad_alloc();
            }
            sodium_memzero(data_, size);
            size_ = size;
        }

        uint8_t* data_ = nullptr;
        size_t size_ = 0;
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_SECURE_BUFFER_HPP
