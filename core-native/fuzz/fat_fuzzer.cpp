#include "filesystem_validation.h"

#include <cstddef>
#include <cstdint>
#include <unordered_set>

namespace {

uint32_t read_le32(const uint8_t* value) {
    return (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
           ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (data == nullptr || size < 8u) return 0;
    const std::size_t entryCount = (size - 4u) / 4u;
    if (entryCount < 3u || entryCount > UINT32_MAX) return 0;
    const uint32_t clusterCount = (uint32_t)entryCount - 2u;
    uint32_t cluster = 2u + read_le32(data) % clusterCount;
    std::unordered_set<uint32_t> visited;
    while (visited.insert(cluster).second && visited.size() <= clusterCount) {
        uint32_t next = 0u;
        const std::size_t offset = 4u + (std::size_t)cluster * 4u;
        if (offset > size || size - offset < 4u ||
            !vc::decode_fat32_chain_entry(data + offset, size - offset,
                                          clusterCount, &next) ||
            next >= 0x0FFFFFF8u) break;
        cluster = next;
    }
    return 0;
}
