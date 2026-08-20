#include "filesystem_validation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

uint16_t read_le16(const uint8_t* value) {
    return (uint16_t)(value[0] | ((uint16_t)value[1] << 8));
}

void write_le16(uint8_t* value, uint16_t input) {
    value[0] = (uint8_t)input;
    value[1] = (uint8_t)(input >> 8);
}

void write_le32(uint8_t* value, uint32_t input) {
    for (unsigned int index = 0u; index < 4u; ++index) {
        value[index] = (uint8_t)(input >> (index * 8u));
    }
}

void write_le64(uint8_t* value, uint64_t input) {
    for (unsigned int index = 0u; index < 8u; ++index) {
        value[index] = (uint8_t)(input >> (index * 8u));
    }
}

std::array<uint8_t, 512u> make_fat32_seed() {
    std::array<uint8_t, 512u> sector{};
    sector[0] = 0xEBu; sector[1] = 0x58u; sector[2] = 0x90u;
    std::memcpy(sector.data() + 3u, "MSDOS5.0", 8u);
    write_le16(sector.data() + 11u, 512u);
    sector[13] = 1u;
    write_le16(sector.data() + 14u, 32u);
    sector[16] = 2u;
    sector[21] = 0xF8u;
    write_le32(sector.data() + 32u, 70000u);
    write_le32(sector.data() + 36u, 600u);
    write_le32(sector.data() + 44u, 2u);
    write_le16(sector.data() + 48u, 1u);
    write_le16(sector.data() + 50u, 6u);
    sector[510] = 0x55u; sector[511] = 0xAAu;
    return sector;
}

std::array<uint8_t, 512u> make_exfat_seed() {
    std::array<uint8_t, 512u> sector{};
    sector[0] = 0xEBu; sector[1] = 0x76u; sector[2] = 0x90u;
    std::memcpy(sector.data() + 3u, "EXFAT   ", 8u);
    write_le64(sector.data() + 72u, 10000u);
    write_le32(sector.data() + 80u, 24u);
    write_le32(sector.data() + 84u, 100u);
    write_le32(sector.data() + 88u, 224u);
    write_le32(sector.data() + 92u, 9000u);
    write_le32(sector.data() + 96u, 2u);
    write_le16(sector.data() + 104u, 0x0100u);
    sector[108] = 9u;
    sector[109] = 0u;
    sector[110] = 1u;
    sector[510] = 0x55u; sector[511] = 0xAAu;
    return sector;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (data == nullptr || size == 0u) return 0;

    // Start most mutations from a structurally valid sector so the fuzzer
    // reaches geometry validation quickly; raw 512-byte inputs are also used.
    std::array<uint8_t, 512u> structured = (data[0] & 1u) == 0u ?
        make_fat32_seed() : make_exfat_seed();
    if ((data[0] & 2u) != 0u && size >= structured.size()) {
        std::memcpy(structured.data(), data, structured.size());
    } else {
        for (std::size_t index = 1u; index < size; ++index) {
            structured[(index - 1u) % structured.size()] ^= data[index];
        }
    }
    data = structured.data();
    size = structured.size();

    vc::Fat32BootFields fat{};
    uint32_t fatSectorSize = read_le16(data + 11);
    if (fatSectorSize < 512u || fatSectorSize > 4096u) fatSectorSize = 512u;
    (void)vc::validate_fat32_boot_sector(data, size, fatSectorSize, UINT64_MAX, &fat);

    vc::ExFatBootFields exfat{};
    const uint8_t shift = data[108];
    const uint32_t exfatSectorSize = shift >= 9u && shift <= 12u ? 1u << shift : 512u;
    (void)vc::validate_exfat_boot_sector(data, size, exfatSectorSize, UINT64_MAX, &exfat);
    return 0;
}
