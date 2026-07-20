package io.veracrypt.android.corenative

import io.veracrypt.android.coreapi.VolumeEntry

/**
 * JNI bridge to the native VeraCrypt parsing library.
 *
 * All public members are safe to call from any thread; heavy work
 * should be dispatched to a background thread by the caller.
 */
object NativeBridge {

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
     * success – stores the master keys and volume parameters in a process-wide
     * session that subsequent calls (e.g. [nativeListDir]) reuse.
     *
     * @param fd       File descriptor of the opened container (read from offset 0).
     * @param password Passphrase bytes (UTF-8).
     * @return 0 = success, -1 = wrong password, -2 = I/O or format error.
     */
    @JvmStatic
    external fun nativeParseHeader(fd: Int, password: ByteArray): Int

    /**
     * List the files and sub-directories at [path] inside the currently open
     * container.
     *
     * [nativeParseHeader] must have returned 0 before calling this function.
     * The native side reads the FAT32 filesystem from [fd] using the master
     * keys stored during header parsing.
     *
     * @param fd   File descriptor of the same container that was opened with
     *             [nativeParseHeader].
     * @param path Absolute path inside the container, e.g. "/" for root.
     * @return Array of [VolumeEntry] items, or null on error / unsupported FS.
     */
    @JvmStatic
    external fun nativeListDir(fd: Int, path: String): Array<VolumeEntry>?

    /**
     * Read up to [length] bytes from the file at [path] inside the currently
     * open container, starting at byte [offset].
     *
     * [nativeParseHeader] must have returned 0 before calling this function.
     * Data is decrypted on-the-fly with AES-256-XTS.
     *
     * @param fd     File descriptor of the container.
     * @param path   Absolute path inside the container, e.g. "/documents/report.pdf".
     * @param offset Byte offset within the file to start reading from.
     * @param length Maximum number of bytes to read (capped at 4 MiB internally).
     * @return The bytes read (may be fewer than [length] at end-of-file),
     *         an empty array at EOF, or null if the file is not found or on I/O error.
     */
    @JvmStatic
    external fun nativeReadFile(fd: Int, path: String, offset: Long, length: Int): ByteArray?

    /**
     * Write [data] into an existing file [path] at [offset].
     *
     * Returns bytes written, or a negative status code:
     *  -1 wrong state/arguments
     *  -2 file not found / unsupported filesystem operation
     *  -3 I/O error
     */
    @JvmStatic
    external fun nativeWriteFile(fd: Int, path: String, offset: Long, data: ByteArray): Int

    /**
     * Allocate [count] clusters in the currently mounted filesystem.
     *
     * Returns first allocated cluster (>1) or a negative status code.
     */
    @JvmStatic
    external fun nativeAllocateClusters(fd: Int, count: Int): Int

    /**
     * Update last-modified metadata for a root-level entry at [path].
     *
     * @return 0 on success, negative on error.
     */
    @JvmStatic
    external fun nativeUpdateTimestamp(fd: Int, path: String, unixTimeMs: Long): Int

    /** Returns 0 unknown, 1 FAT32, 2 exFAT, 3 NTFS. */
    @JvmStatic
    external fun nativeGetFileSystemType(fd: Int): Int

    /**
     * Create a new encrypted container image.
     *
     * @param fd writable file descriptor.
     * @param password passphrase bytes (UTF-8).
     * @param entropy additional caller entropy bytes.
     * @param containerSizeBytes output file size in bytes.
     * @param fsType 1 FAT32, 2 exFAT, 3 NTFS.
     * @return 0 on success, negative on error.
     */
    @JvmStatic
    external fun nativeCreateContainer(
        fd: Int,
        password: ByteArray,
        entropy: ByteArray,
        containerSizeBytes: Long,
        fsType: Int
    ): Int

    /**
     * Root-only best-effort mount integration hook.
     *
     * Native side currently validates parameters and prepares mount metadata.
     * Returns 0 when the request is accepted.
     */
    @JvmStatic
    external fun nativePrepareFuseMount(fd: Int, mountPoint: String, readWrite: Boolean): Int

    /** Convenience: returns the native library version. */
    fun version(): String = nativeGetVersion()
}
