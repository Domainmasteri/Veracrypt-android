#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace vc {

constexpr std::size_t kMaxUtf8NameBytes = 1024u;

struct Fat32BootFields {
    uint16_t bytesPerSector;
    uint8_t sectorsPerCluster;
    uint16_t reservedSectors;
    uint8_t numberOfFats;
    uint32_t sectorsPerFat;
    uint32_t rootCluster;
    uint16_t fsInfoSector;
    uint16_t backupBootSector;
    uint32_t firstDataSector;
    uint32_t clusterCount;
};

struct ExFatBootFields {
    uint64_t volumeLength;
    uint32_t fatOffset;
    uint32_t fatLength;
    uint32_t clusterHeapOffset;
    uint32_t clusterCount;
    uint32_t rootCluster;
    uint8_t bytesPerSectorShift;
    uint8_t sectorsPerClusterShift;
    uint8_t numberOfFats;
    uint16_t volumeFlags;
    uint16_t bytesPerSector;
    uint32_t sectorsPerCluster;
};

struct FatLfnEntryFields {
    uint8_t sequence;
    bool isLast;
    uint8_t checksum;
    std::u16string characters;
};

struct ExFatFileEntryFields {
    std::string name;
    bool isDirectory;
    bool noFatChain;
    uint16_t modifiedDate;
    uint16_t modifiedTime;
    uint32_t firstCluster;
    uint64_t validDataLength;
    uint64_t dataLength;
};

bool validate_fat32_boot_sector(const uint8_t* sector, std::size_t sectorLength,
                                uint32_t sessionSectorSize, uint64_t availableSectors,
                                Fat32BootFields* output);

bool validate_exfat_boot_sector(const uint8_t* sector, std::size_t sectorLength,
                                uint32_t sessionSectorSize, uint64_t availableSectors,
                                ExFatBootFields* output);

bool utf16_to_utf8_strict(const char16_t* input, std::size_t length,
                          std::string* output);

// Decode a FAT32 chain entry and reject free, reserved, bad and out-of-range
// values. End-of-chain values are returned unchanged.
bool decode_fat32_chain_entry(const uint8_t* entry, std::size_t length,
                              uint32_t clusterCount, uint32_t* nextCluster);

// Parse one 32-byte FAT long-file-name record, including its structural
// fields and UTF-16 padding rules.
bool parse_fat_lfn_entry(const uint8_t* entry, std::size_t length,
                         FatLfnEntryFields* output);

// Validate and parse one complete exFAT File entry set (primary entry followed
// by all declared secondary entries), including its set checksum.
bool parse_exfat_file_entry_set(const uint8_t* entries, std::size_t length,
                                ExFatFileEntryFields* output);

uint8_t fat_lfn_checksum(const uint8_t shortName[11]);

uint16_t exfat_set_checksum_update(uint16_t checksum, const uint8_t entry[32],
                                   bool primaryEntry);

}  // namespace vc
