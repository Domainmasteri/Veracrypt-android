#pragma once

#include <cstdint>
#include <limits>

inline bool checked_add_u64(uint64_t left, uint64_t right, uint64_t* result) {
    if (right > std::numeric_limits<uint64_t>::max() - left) return false;
    *result = left + right;
    return true;
}

inline bool checked_mul_u64(uint64_t left, uint64_t right, uint64_t* result) {
    if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) return false;
    *result = left * right;
    return true;
}

