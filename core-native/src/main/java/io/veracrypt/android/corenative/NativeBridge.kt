package io.veracrypt.android.corenative

import io.veracrypt.android.coreapi.ContainerReader
import io.veracrypt.android.coreapi.OpenResult
import io.veracrypt.android.coreapi.VolumeEntry

/**
 * JNI bridge to the native VeraCrypt parsing library.
 *
 * All public members are safe to call from any thread; heavy work
 * should be dispatched to a background coroutine by the caller.
 */
object NativeBridge {

    init {
        System.loadLibrary("veracrypt-native")
    }

    /** Returns the version string from the native library (e.g. "0.1.0-stub"). */
    @JvmStatic
    external fun nativeGetVersion(): String

    /**
     * Attempt to parse and decrypt the volume header.
     *
     * @param headerBytes First 512 bytes of the container file.
     * @param password    Passphrase bytes (UTF-8).
     * @return 0 = success, -1 = wrong password, -2 = format error.
     */
    @JvmStatic
    external fun nativeParseHeader(headerBytes: ByteArray, password: ByteArray): Int

    /** Convenience: returns the native library version. */
    fun version(): String = nativeGetVersion()
}
