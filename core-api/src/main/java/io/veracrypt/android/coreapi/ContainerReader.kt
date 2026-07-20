package io.veracrypt.android.coreapi

import java.io.Closeable

/**
 * Result of attempting to open and verify a VeraCrypt container.
 */
sealed class OpenResult {
    /** The header was decrypted successfully; [header] contains volume metadata. */
    data class Success(val header: VolumeHeader) : OpenResult()

    /** The provided password/keyfile was incorrect. */
    object WrongPassword : OpenResult()

    /** The file is not a recognised VeraCrypt/TrueCrypt container. */
    object NotAContainer : OpenResult()

    /** An I/O or unexpected error occurred. */
    data class Error(val message: String, val cause: Throwable? = null) : OpenResult()
}

/**
 * Minimal read-only interface for accessing content inside a VeraCrypt container.
 *
 * Implementations must be thread-safe and [Closeable].
 */
interface ContainerReader : Closeable {

    /**
     * Attempt to open the volume using the supplied [password] and optional [keyfileBytes].
     *
     * @return [OpenResult] indicating success or the reason for failure.
     */
    fun open(password: CharArray, keyfileBytes: ByteArray? = null): OpenResult

    /**
     * List the entries (files and directories) at the given [path] inside the volume.
     *
     * @param path Absolute path inside the container, e.g. "/" for the root directory.
     * @return List of [VolumeEntry] items, or an empty list if the path does not exist.
     * @throws IllegalStateException if the volume has not been successfully opened.
     */
    fun list(path: String): List<VolumeEntry>

    /**
     * Read up to [length] bytes from [path] starting at [offset].
     *
     * @return The bytes read, which may be fewer than [length] at end-of-file.
     * @throws IllegalStateException if the volume has not been successfully opened.
     * @throws java.io.FileNotFoundException if [path] does not exist.
     */
    fun read(path: String, offset: Long, length: Int): ByteArray
}

/**
 * Metadata for a single file or directory inside a container.
 */
data class VolumeEntry(
    val name: String,
    val path: String,
    val isDirectory: Boolean,
    val sizeBytes: Long,
    val lastModifiedMs: Long
)
