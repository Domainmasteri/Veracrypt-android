package io.veracrypt.android.corenative

import io.veracrypt.android.coreapi.VolumeEntry

/**
 * JNI bridge to the native VeraCrypt parsing library.
 *
 * All public members are safe to call from any thread; heavy work
 * should be dispatched to a background thread by the caller.
 */
object NativeBridge {

    const val OPEN_WRONG_PASSWORD: Long = -1L
    const val OPEN_IO_OR_FORMAT_ERROR: Long = -2L
    const val OPEN_CORRUPT_HEADER: Long = -3L
    const val OPEN_UNSUPPORTED_HEADER: Long = -4L
    const val OPEN_INVALID_FORMAT: Long = -5L
    const val FS_UNKNOWN: Int = 0
    const val FS_FAT32: Int = 1
    const val FS_EXFAT: Int = 2
    const val FS_NTFS: Int = 3

    init {
        System.loadLibrary("veracrypt-native")
    }

    /** Returns the version string from the native library (e.g. "0.2.0"). */
    @JvmStatic
    external fun nativeGetVersion(): String

    /**
     * Attempt to parse and decrypt the volume header.
     *
     * Reads the first 512 bytes from [fd], derives the encryption key via
     * PBKDF2-HMAC-SHA512, decrypts the header with AES-256-XTS, and – on
     * success – creates an independently owned opaque session.
     *
     * @param fd       File descriptor of the opened container (read from offset 0).
     * @param password Passphrase bytes (UTF-8).
     * @return Positive opaque handle on success, otherwise an `OPEN_*` status.
     */
    @JvmStatic
    external fun nativeOpen(fd: Int, password: ByteArray): Long

    /** Close an opened session. Safe to call more than once. */
    @JvmStatic
    external fun nativeClose(sessionHandle: Long)

    /** Returns true only while [sessionHandle] identifies an open native session. */
    @JvmStatic
    external fun nativeIsOpen(sessionHandle: Long): Boolean

    /** Run built-in, dependency-independent cryptographic known-answer tests. */
    @JvmStatic
    external fun nativeRunCryptoSelfTests(): Boolean

    /** Run deterministic parser boundary, Unicode and 64-bit-size self-tests. */
    @JvmStatic
    external fun nativeRunFilesystemSelfTests(): Boolean

    /**
     * List the files and sub-directories at [path] inside the currently open
     * container.
     *
     * [nativeOpen] must have returned [sessionHandle] before this call.
     *
     * @param sessionHandle Opaque positive handle returned by [nativeOpen].
     * @param path Absolute path inside the container, e.g. "/" for root.
     * @return Array of [VolumeEntry] items, or null on error / unsupported FS.
     */
    @JvmStatic
    external fun nativeListDir(sessionHandle: Long, path: String): Array<VolumeEntry>?

    /**
     * Read up to [length] bytes from the file at [path] inside the currently
     * open container, starting at byte [offset].
     *
     * [nativeOpen] must have returned the supplied handle before this call.
     * Data is decrypted on-the-fly with AES-256-XTS.
     *
     * @param sessionHandle Opaque positive handle returned by [nativeOpen].
     * @param path   Absolute path inside the container, e.g. "/documents/report.pdf".
     * @param offset Byte offset within the file to start reading from.
     * @param length Maximum number of bytes to read (capped at 4 MiB internally).
     * @return The bytes read (may be fewer than [length] at end-of-file),
     *         an empty array at EOF, or null if the file is not found or on I/O error.
     */
    @JvmStatic
    external fun nativeReadFile(
        sessionHandle: Long,
        path: String,
        offset: Long,
        length: Int
    ): ByteArray?

    /** Returns 0 unknown, 1 FAT32, 2 exFAT, 3 NTFS. */
    @JvmStatic
    external fun nativeGetFileSystemType(sessionHandle: Long): Int

    /** Convenience: returns the native library version. */
    fun version(): String = nativeGetVersion()
}
