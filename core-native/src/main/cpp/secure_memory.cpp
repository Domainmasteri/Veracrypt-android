#include "secure_memory.h"

void secure_zero(void* data, std::size_t length) noexcept {
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (length-- > 0) *cursor++ = 0;
}

bool secure_equal(const uint8_t* left, const uint8_t* right, std::size_t length) noexcept {
    uint8_t difference = 0;
    for (std::size_t index = 0; index < length; ++index) {
        difference |= static_cast<uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

