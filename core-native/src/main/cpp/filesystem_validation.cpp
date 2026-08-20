#include "filesystem_validation.h"

#include <climits>
#include <cstring>

namespace vc {
namespace {

uint16_t read_le16(const uint8_t* value) {
    return (uint16_t)(value[0] | ((uint16_t)value[1] << 8));
}

uint32_t read_le32(const uint8_t* value) {
    return (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
           ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
}

uint64_t read_le64(const uint8_t* value) {
    return (uint64_t)read_le32(value) | ((uint64_t)read_le32(value + 4) << 32);
}

int encode_codepoint(uint32_t codepoint, char output[4]) {
    if (codepoint <= 0x7Fu) {
        output[0] = (char)codepoint;
        return 1;
    }
    if (codepoint <= 0x7FFu) {
        output[0] = (char)(0xC0u | (codepoint >> 6));
        output[1] = (char)(0x80u | (codepoint & 0x3Fu));
        return 2;
    }
    if (codepoint <= 0xFFFFu && (codepoint < 0xD800u || codepoint > 0xDFFFu)) {
        output[0] = (char)(0xE0u | (codepoint >> 12));
        output[1] = (char)(0x80u | ((codepoint >> 6) & 0x3Fu));
        output[2] = (char)(0x80u | (codepoint & 0x3Fu));
        return 3;
    }
    if (codepoint <= 0x10FFFFu) {
        output[0] = (char)(0xF0u | (codepoint >> 18));
        output[1] = (char)(0x80u | ((codepoint >> 12) & 0x3Fu));
        output[2] = (char)(0x80u | ((codepoint >> 6) & 0x3Fu));
        output[3] = (char)(0x80u | (codepoint & 0x3Fu));
        return 4;
    }
    return 0;
}

}  // namespace

bool validate_fat32_boot_sector(const uint8_t* sector, std::size_t sectorLength,
                                uint32_t sessionSectorSize, uint64_t availableSectors,
                                Fat32BootFields* output) {
    if (sector == nullptr || output == nullptr || sectorLength < 512u) return false;
    const uint16_t bytesPerSector = read_le16(sector + 11);
    const uint8_t sectorsPerCluster = sector[13];
    const uint16_t reservedSectors = read_le16(sector + 14);
    const uint8_t numberOfFats = sector[16];
    const uint16_t rootEntries = read_le16(sector + 17);
    const uint16_t total16 = read_le16(sector + 19);
    const uint8_t media = sector[21];
    const uint16_t sectorsPerFat16 = read_le16(sector + 22);
    const uint32_t total32 = read_le32(sector + 32);
    const uint32_t sectorsPerFat = read_le32(sector + 36);
    const uint32_t rootCluster = read_le32(sector + 44);
    const uint16_t fsInfoSector = read_le16(sector + 48);
    const uint16_t backupBootSector = read_le16(sector + 50);
    const uint64_t totalSectors = total16 != 0u ? total16 : total32;
    const uint64_t firstData = (uint64_t)reservedSectors +
                               (uint64_t)numberOfFats * sectorsPerFat;
    const uint64_t dataSectors = firstData < totalSectors ? totalSectors - firstData : 0u;
    const uint64_t clusterCount = sectorsPerCluster == 0u ? 0u :
                                  dataSectors / sectorsPerCluster;
    const uint64_t fatCapacity = ((uint64_t)sectorsPerFat * bytesPerSector) / 4u;
    const bool powerOfTwoCluster = sectorsPerCluster != 0u &&
                                   (sectorsPerCluster & (sectorsPerCluster - 1u)) == 0u;
    const bool validJump = sector[0] == 0xE9u ||
                           (sector[0] == 0xEBu && sector[2] == 0x90u);

    if (!validJump || bytesPerSector != sessionSectorSize || bytesPerSector < 512u ||
        bytesPerSector > 4096u || sectorLength < bytesPerSector ||
        !powerOfTwoCluster || sectorsPerCluster > 128u || numberOfFats == 0u ||
        numberOfFats > 2u || sectorsPerFat == 0u || reservedSectors == 0u ||
        totalSectors == 0u || totalSectors > availableSectors || firstData >= totalSectors ||
        clusterCount < 1u || clusterCount > UINT32_MAX - 1u ||
        fatCapacity < clusterCount + 2u || rootCluster < 2u ||
        rootCluster > clusterCount + 1u || rootEntries != 0u ||
        sectorsPerFat16 != 0u || media < 0xF0u || fsInfoSector == 0u ||
        fsInfoSector == 0xFFFFu || fsInfoSector >= reservedSectors ||
        backupBootSector == 0u || backupBootSector == 0xFFFFu ||
        backupBootSector >= reservedSectors || sector[510] != 0x55u ||
        sector[511] != 0xAAu) {
        return false;
    }

    *output = {(uint16_t)bytesPerSector, sectorsPerCluster, reservedSectors,
               numberOfFats, sectorsPerFat, rootCluster, fsInfoSector,
               backupBootSector, (uint32_t)firstData, (uint32_t)clusterCount};
    return true;
}

bool validate_exfat_boot_sector(const uint8_t* sector, std::size_t sectorLength,
                                uint32_t sessionSectorSize, uint64_t availableSectors,
                                ExFatBootFields* output) {
    if (sector == nullptr || output == nullptr || sectorLength < 512u ||
        sector[0] != 0xEBu || sector[1] != 0x76u || sector[2] != 0x90u ||
        std::memcmp(sector + 3, "EXFAT   ", 8) != 0) return false;
    for (std::size_t index = 11u; index <= 63u; ++index) {
        if (sector[index] != 0u) return false;
    }

    const uint64_t volumeLength = read_le64(sector + 72);
    const uint32_t fatOffset = read_le32(sector + 80);
    const uint32_t fatLength = read_le32(sector + 84);
    const uint32_t clusterHeapOffset = read_le32(sector + 88);
    const uint32_t clusterCount = read_le32(sector + 92);
    const uint32_t rootCluster = read_le32(sector + 96);
    const uint16_t revision = read_le16(sector + 104);
    const uint16_t volumeFlags = read_le16(sector + 106);
    const uint8_t bytesPerSectorShift = sector[108];
    const uint8_t sectorsPerClusterShift = sector[109];
    const uint8_t numberOfFats = sector[110];
    if (bytesPerSectorShift < 9u || bytesPerSectorShift > 12u ||
        sectorsPerClusterShift > 25u - bytesPerSectorShift) return false;
    const uint32_t bytesPerSector = 1u << bytesPerSectorShift;
    const uint32_t sectorsPerCluster = 1u << sectorsPerClusterShift;
    const uint64_t fatEnd = (uint64_t)fatOffset + (uint64_t)fatLength * numberOfFats;
    const uint64_t heapEnd = (uint64_t)clusterHeapOffset +
                             (uint64_t)clusterCount * sectorsPerCluster;
    const uint64_t fatCapacity = ((uint64_t)fatLength * bytesPerSector) / 4u;
    const uint8_t activeFat = (uint8_t)(volumeFlags & 1u);

    if (bytesPerSector != sessionSectorSize || sectorLength < bytesPerSector ||
        revision != 0x0100u || volumeLength < 24u || volumeLength > availableSectors ||
        fatOffset < 24u || fatLength == 0u || clusterCount == 0u ||
        rootCluster < 2u || rootCluster > clusterCount + 1u ||
        fatCapacity < (uint64_t)clusterCount + 2u || numberOfFats < 1u ||
        numberOfFats > 2u || activeFat >= numberOfFats || (volumeFlags & 0xFFF8u) != 0u ||
        (volumeFlags & 0x0006u) != 0u || fatEnd > volumeLength ||
        clusterHeapOffset < fatEnd || clusterHeapOffset >= volumeLength ||
        heapEnd > volumeLength || sector[510] != 0x55u || sector[511] != 0xAAu) {
        return false;
    }

    *output = {volumeLength, fatOffset, fatLength, clusterHeapOffset, clusterCount,
               rootCluster, bytesPerSectorShift, sectorsPerClusterShift,
               numberOfFats, volumeFlags, (uint16_t)bytesPerSector,
               sectorsPerCluster};
    return true;
}

bool utf16_to_utf8_strict(const char16_t* input, std::size_t length,
                          std::string* output) {
    if (output == nullptr || (input == nullptr && length != 0u)) return false;
    output->clear();
    uint16_t high = 0u;
    for (std::size_t index = 0; index < length; ++index) {
        const uint16_t unit = (uint16_t)input[index];
        uint32_t codepoint = unit;
        if (high != 0u) {
            if (unit < 0xDC00u || unit > 0xDFFFu) return false;
            codepoint = 0x10000u + (((uint32_t)high - 0xD800u) << 10) +
                        ((uint32_t)unit - 0xDC00u);
            high = 0u;
        } else if (unit >= 0xD800u && unit <= 0xDBFFu) {
            high = unit;
            continue;
        } else if (unit >= 0xDC00u && unit <= 0xDFFFu) {
            return false;
        }
        char encoded[4];
        const int count = encode_codepoint(codepoint, encoded);
        if (count == 0 || output->size() + (std::size_t)count > kMaxUtf8NameBytes) {
            output->clear();
            return false;
        }
        output->append(encoded, (std::size_t)count);
    }
    if (high != 0u || output->empty()) {
        output->clear();
        return false;
    }
    return true;
}

bool decode_fat32_chain_entry(const uint8_t* entry, std::size_t length,
                              uint32_t clusterCount, uint32_t* nextCluster) {
    if (entry == nullptr || nextCluster == nullptr || length < 4u || clusterCount == 0u ||
        clusterCount > 0x0FFFFFEDu) return false;
    const uint32_t value = read_le32(entry) & 0x0FFFFFFFu;
    if (value >= 0x0FFFFFF8u) {
        *nextCluster = value;
        return true;
    }
    // 0/1 are free/reserved, 0x0FFFFFF0..7 are reserved/bad, and a data
    // cluster must be inside the volume's declared cluster range.
    if (value < 2u || value >= 0x0FFFFFF0u || value > clusterCount + 1u) return false;
    *nextCluster = value;
    return true;
}

bool parse_fat_lfn_entry(const uint8_t* entry, std::size_t length,
                         FatLfnEntryFields* output) {
    if (entry == nullptr || output == nullptr || length < 32u || entry[11] != 0x0Fu ||
        entry[12] != 0u || read_le16(entry + 26) != 0u || (entry[0] & 0x80u) != 0u ||
        (entry[0] & 0x20u) != 0u) return false;
    const uint8_t sequence = entry[0] & 0x1Fu;
    if (sequence == 0u || sequence > 20u) return false;

    static constexpr std::size_t offsets[] = {
        1u, 3u, 5u, 7u, 9u, 14u, 16u, 18u, 20u, 22u, 24u, 28u, 30u
    };
    std::u16string characters;
    bool terminated = false;
    for (std::size_t offset : offsets) {
        const uint16_t value = read_le16(entry + offset);
        if (terminated) {
            if (value != 0xFFFFu) return false;
        } else if (value == 0u) {
            terminated = true;
        } else if (value == 0xFFFFu) {
            return false;
        } else {
            characters.push_back((char16_t)value);
        }
    }
    if (characters.empty() && !terminated) return false;
    *output = {sequence, (entry[0] & 0x40u) != 0u, entry[13], std::move(characters)};
    return true;
}

bool parse_exfat_file_entry_set(const uint8_t* entries, std::size_t length,
                                ExFatFileEntryFields* output) {
    if (entries == nullptr || output == nullptr || length < 3u * 32u ||
        entries[0] != 0x85u) return false;
    const uint8_t secondaryCount = entries[1];
    const std::size_t expectedLength = ((std::size_t)secondaryCount + 1u) * 32u;
    if (secondaryCount < 2u || secondaryCount > 18u || length != expectedLength) return false;

    const uint16_t expectedChecksum = read_le16(entries + 2);
    uint16_t checksum = exfat_set_checksum_update(0u, entries, true);
    for (std::size_t index = 1u; index <= secondaryCount; ++index) {
        const uint8_t* entry = entries + index * 32u;
        if ((entry[0] & 0x80u) == 0u) return false;
        checksum = exfat_set_checksum_update(checksum, entry, false);
    }
    if (checksum != expectedChecksum) return false;

    const uint8_t* stream = entries + 32u;
    if (stream[0] != 0xC0u || (stream[1] & 0xFCu) != 0u) return false;
    const uint8_t nameLength = stream[3];
    if (nameLength == 0u) return false;
    const std::size_t requiredNameEntries = ((std::size_t)nameLength + 14u) / 15u;
    if (requiredNameEntries + 1u != secondaryCount) return false;

    std::u16string utf16Name;
    utf16Name.reserve(nameLength);
    for (std::size_t index = 2u; index <= secondaryCount; ++index) {
        const uint8_t* nameEntry = entries + index * 32u;
        if (nameEntry[0] != 0xC1u || nameEntry[1] != 0u) return false;
        for (std::size_t character = 0u; character < 15u; ++character) {
            const uint16_t value = read_le16(nameEntry + 2u + character * 2u);
            if (utf16Name.size() < nameLength) {
                if (value == 0u || value == 0xFFFFu) return false;
                utf16Name.push_back((char16_t)value);
            } else if (value != 0u && value != 0xFFFFu) {
                return false;
            }
        }
    }
    std::string name;
    if (utf16Name.size() != nameLength ||
        !utf16_to_utf8_strict(utf16Name.data(), utf16Name.size(), &name) ||
        name == "." || name == ".." || name.find('/') != std::string::npos ||
        name.find('\\') != std::string::npos) return false;

    const uint64_t validDataLength = read_le64(stream + 8);
    const uint64_t dataLength = read_le64(stream + 24);
    if (validDataLength > dataLength) return false;
    const uint32_t timestamp = read_le32(entries + 12);
    *output = {std::move(name), (read_le16(entries + 4) & 0x10u) != 0u,
               (stream[1] & 0x02u) != 0u, (uint16_t)(timestamp >> 16),
               (uint16_t)timestamp, read_le32(stream + 20), validDataLength,
               dataLength};
    return true;
}

uint8_t fat_lfn_checksum(const uint8_t shortName[11]) {
    if (shortName == nullptr) return 0u;
    uint8_t checksum = 0u;
    for (std::size_t index = 0; index < 11u; ++index) {
        checksum = (uint8_t)(((checksum & 1u) ? 0x80u : 0u) +
                             (checksum >> 1u) + shortName[index]);
    }
    return checksum;
}

uint16_t exfat_set_checksum_update(uint16_t checksum, const uint8_t entry[32],
                                   bool primaryEntry) {
    if (entry == nullptr) return checksum;
    for (std::size_t index = 0; index < 32u; ++index) {
        if (primaryEntry && (index == 2u || index == 3u)) continue;
        checksum = (uint16_t)(((checksum << 15u) | (checksum >> 1u)) + entry[index]);
    }
    return checksum;
}

}  // namespace vc
