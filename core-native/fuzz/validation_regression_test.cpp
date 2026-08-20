#include "filesystem_validation.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

namespace {

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

bool check(bool condition, const char* message) {
    if (!condition) std::cerr << message << '\n';
    return condition;
}

}  // namespace

int main() {
    std::array<uint8_t, 512u> fat{};
    fat[0] = 0xEBu; fat[1] = 0x58u; fat[2] = 0x90u;
    write_le16(fat.data() + 11u, 512u);
    fat[13] = 1u;
    write_le16(fat.data() + 14u, 32u);
    fat[16] = 2u;
    fat[21] = 0xF8u;
    write_le32(fat.data() + 32u, 70000u);
    write_le32(fat.data() + 36u, 600u);
    write_le32(fat.data() + 44u, 2u);
    write_le16(fat.data() + 48u, 1u);
    write_le16(fat.data() + 50u, 6u);
    fat[510] = 0x55u; fat[511] = 0xAAu;
    vc::Fat32BootFields fatFields{};
    if (!check(vc::validate_fat32_boot_sector(fat.data(), fat.size(), 512u,
                                               70000u, &fatFields),
               "valid FAT32 BPB rejected")) return 1;
    fat[510] = 0u;
    if (!check(!vc::validate_fat32_boot_sector(fat.data(), fat.size(), 512u,
                                                70000u, &fatFields),
               "bad FAT32 signature accepted")) return 1;

    std::array<uint8_t, 512u> exfat{};
    exfat[0] = 0xEBu; exfat[1] = 0x76u; exfat[2] = 0x90u;
    std::memcpy(exfat.data() + 3u, "EXFAT   ", 8u);
    write_le64(exfat.data() + 72u, 10000u);
    write_le32(exfat.data() + 80u, 24u);
    write_le32(exfat.data() + 84u, 100u);
    write_le32(exfat.data() + 88u, 224u);
    write_le32(exfat.data() + 92u, 9000u);
    write_le32(exfat.data() + 96u, 2u);
    write_le16(exfat.data() + 104u, 0x0100u);
    exfat[108] = 9u; exfat[110] = 1u;
    exfat[510] = 0x55u; exfat[511] = 0xAAu;
    vc::ExFatBootFields exfatFields{};
    if (!check(vc::validate_exfat_boot_sector(exfat.data(), exfat.size(), 512u,
                                               10000u, &exfatFields),
               "valid exFAT BPB rejected")) return 1;
    write_le16(exfat.data() + 106u, 0x0002u);
    if (!check(!vc::validate_exfat_boot_sector(exfat.data(), exfat.size(), 512u,
                                                10000u, &exfatFields),
               "dirty exFAT volume accepted")) return 1;

    std::array<uint8_t, 4u> chain{};
    write_le32(chain.data(), 7u);
    uint32_t next = 0u;
    if (!check(vc::decode_fat32_chain_entry(chain.data(), chain.size(), 100u, &next) &&
                   next == 7u, "valid FAT chain entry rejected")) return 1;
    write_le32(chain.data(), 0x0FFFFFF7u);
    if (!check(!vc::decode_fat32_chain_entry(chain.data(), chain.size(), 100u, &next),
               "bad FAT cluster accepted")) return 1;

    std::array<uint8_t, 32u> lfn{};
    lfn.fill(0xFFu);
    lfn[0] = 0x41u; lfn[11] = 0x0Fu; lfn[12] = 0u; lfn[13] = 0x5Au;
    write_le16(lfn.data() + 26u, 0u);
    write_le16(lfn.data() + 1u, (uint16_t)'A');
    write_le16(lfn.data() + 3u, 0u);
    vc::FatLfnEntryFields lfnFields{};
    if (!check(vc::parse_fat_lfn_entry(lfn.data(), lfn.size(), &lfnFields) &&
                   lfnFields.characters == u"A", "valid FAT LFN rejected")) return 1;
    lfn[12] = 1u;
    if (!check(!vc::parse_fat_lfn_entry(lfn.data(), lfn.size(), &lfnFields),
               "malformed FAT LFN accepted")) return 1;

    std::array<uint8_t, 96u> fileSet{};
    fileSet[0] = 0x85u; fileSet[1] = 2u;
    fileSet[32] = 0xC0u; fileSet[33] = 0x02u; fileSet[35] = 9u;
    constexpr uint64_t fiveGiB = 5ull * 1024ull * 1024ull * 1024ull;
    write_le64(fileSet.data() + 40u, fiveGiB);
    write_le32(fileSet.data() + 52u, 2u);
    write_le64(fileSet.data() + 56u, fiveGiB);
    fileSet[64] = 0xC1u;
    const std::u16string name = u"large.bin";
    for (std::size_t index = 0u; index < name.size(); ++index) {
        write_le16(fileSet.data() + 66u + index * 2u, (uint16_t)name[index]);
    }
    uint16_t checksum = vc::exfat_set_checksum_update(0u, fileSet.data(), true);
    checksum = vc::exfat_set_checksum_update(checksum, fileSet.data() + 32u, false);
    checksum = vc::exfat_set_checksum_update(checksum, fileSet.data() + 64u, false);
    write_le16(fileSet.data() + 2u, checksum);
    vc::ExFatFileEntryFields fileFields{};
    if (!check(vc::parse_exfat_file_entry_set(fileSet.data(), fileSet.size(), &fileFields) &&
                   fileFields.name == "large.bin" && fileFields.dataLength == fiveGiB,
               "64-bit exFAT file entry set rejected or truncated")) return 1;
    fileSet[2] ^= 1u;
    if (!check(!vc::parse_exfat_file_entry_set(fileSet.data(), fileSet.size(), &fileFields),
               "bad exFAT entry-set checksum accepted")) return 1;
    return 0;
}
