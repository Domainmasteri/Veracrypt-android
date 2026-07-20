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

    /** Convenience: returns the native library version. */
    fun version(): String = nativeGetVersion()
}

