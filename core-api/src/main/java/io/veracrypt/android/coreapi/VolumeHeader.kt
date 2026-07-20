package io.veracrypt.android.coreapi

/**
 * Supported VeraCrypt/TrueCrypt encryption algorithms.
 */
enum class EncryptionAlgorithm {
    AES,
    SERPENT,
    TWOFISH,
    AES_TWOFISH,
    AES_TWOFISH_SERPENT,
    SERPENT_AES,
    SERPENT_TWOFISH_AES,
    TWOFISH_SERPENT,
    UNKNOWN
}

/**
 * Supported hash algorithms used for key derivation.
 */
enum class HashAlgorithm {
    SHA512,
    WHIRLPOOL,
    SHA256,
    RIPEMD160,
    UNKNOWN
}

/**
 * Parsed representation of a VeraCrypt volume header.
 *
 * @param magic          The 4-byte magic bytes ("VERA" for VeraCrypt, "TRUE" for TrueCrypt).
 * @param version        Volume format version.
 * @param minProgramVersion Minimum program version required to open this volume.
 * @param volumeSize     Size of the volume in bytes.
 * @param encryptionAlgorithm Cipher used to encrypt the volume data.
 * @param hashAlgorithm  PRF hash used for key derivation (PBKDF2).
 * @param sectorSize     Sector size in bytes.
 * @param isVeraCrypt    True when the magic matches VeraCrypt ("VERA"), false for TrueCrypt.
 */
data class VolumeHeader(
    val magic: String,
    val version: Int,
    val minProgramVersion: Int,
    val volumeSize: Long,
    val encryptionAlgorithm: EncryptionAlgorithm,
    val hashAlgorithm: HashAlgorithm,
    val sectorSize: Int,
    val isVeraCrypt: Boolean
)
