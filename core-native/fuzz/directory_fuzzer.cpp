#include "filesystem_validation.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (data == nullptr) return 0;
    for (std::size_t offset = 0u; offset <= size && size - offset >= 32u;
         offset += 32u) {
        vc::FatLfnEntryFields lfn{};
        (void)vc::parse_fat_lfn_entry(data + offset, size - offset, &lfn);
    }

    vc::ExFatFileEntryFields exfat{};
    (void)vc::parse_exfat_file_entry_set(data, size, &exfat);

    const std::size_t unitCount = size / 2u;
    std::vector<char16_t> units;
    units.reserve(unitCount);
    for (std::size_t index = 0u; index < unitCount; ++index) {
        units.push_back((char16_t)((uint16_t)data[index * 2u] |
                                  ((uint16_t)data[index * 2u + 1u] << 8)));
    }
    std::string utf8;
    (void)vc::utf16_to_utf8_strict(units.data(), units.size(), &utf8);
    return 0;
}
