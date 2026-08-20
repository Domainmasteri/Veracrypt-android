#pragma once

#include <cstddef>
#include <cstdint>

void secure_zero(void* data, std::size_t length) noexcept;
bool secure_equal(const uint8_t* left, const uint8_t* right, std::size_t length) noexcept;

class ScopedWipe {
public:
    ScopedWipe(void* data, std::size_t length) noexcept : data_(data), length_(length) {}
    ~ScopedWipe() { secure_zero(data_, length_); }
    ScopedWipe(const ScopedWipe&) = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;

private:
    void* data_;
    std::size_t length_;
};
