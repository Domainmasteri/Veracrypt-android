package io.veracrypt.android.corenative

import io.veracrypt.android.coreapi.VolumeEntry
import java.io.Closeable
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

sealed interface SessionOpenResult {
    data class Success(val session: ContainerSession) : SessionOpenResult
    data object WrongPassword : SessionOpenResult
    data object CorruptHeader : SessionOpenResult
    data object UnsupportedHeader : SessionOpenResult
    data object UnsupportedFileSystem : SessionOpenResult
    data object InvalidFormat : SessionOpenResult
    data object IoError : SessionOpenResult
}

/**
 * Owns one opaque native container session.
 *
 * Operations are serialized on a dedicated worker. Closing queues native key
 * destruction after already accepted work and rejects every later operation.
 */
class ContainerSession internal constructor(
    internal val handle: Long
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val gate = Any()
    private val cancellationCallbacks = java.util.concurrent.ConcurrentHashMap<Long, () -> Unit>()
    private val nextCancellationId = AtomicLong(1L)
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "veracrypt-session").apply { isDaemon = true }
    }

    val isOpen: Boolean
        get() = !closed.get() && NativeBridge.nativeIsOpen(handle)

    fun list(path: String): Array<VolumeEntry>? = execute {
        NativeBridge.nativeListDir(handle, path)
    }

    fun read(path: String, offset: Long, length: Int): ByteArray? = execute {
        NativeBridge.nativeReadFile(handle, path, offset, length)
    }

    fun fileSystemType(): Int = execute {
        NativeBridge.nativeGetFileSystemType(handle)
    }

    /** Registers work that must be cancelled before native keys/fd are destroyed. */
    fun onClose(cancel: () -> Unit): Closeable {
        val id = nextCancellationId.getAndIncrement()
        if (closed.get()) {
            cancel()
            return Closeable { }
        }
        cancellationCallbacks[id] = cancel
        if (closed.get() && cancellationCallbacks.remove(id) != null) cancel()
        return Closeable { cancellationCallbacks.remove(id) }
    }

    private fun <T> execute(block: () -> T): T {
        val future = synchronized(gate) {
            check(!closed.get()) { "Container session is closed" }
            worker.submit(Callable(block))
        }
        return try {
            future.get()
        } catch (error: ExecutionException) {
            throw error.cause ?: error
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        cancellationCallbacks.values.forEach { cancel -> runCatching(cancel) }
        cancellationCallbacks.clear()
        val closeFuture = synchronized(gate) {
            worker.submit { NativeBridge.nativeClose(handle) }
        }
        try {
            closeFuture.get()
        } finally {
            worker.shutdown()
        }
    }
}

/** Process-local owner of the session currently exposed through Android UI/SAF. */
object ContainerSessionManager {
    private val active = AtomicReference<ContainerSession?>(null)

    fun open(fd: Int, password: ByteArray): SessionOpenResult {
        val handle = NativeBridge.nativeOpen(fd, password)
        return when {
            handle > 0L -> {
                val session = ContainerSession(handle)
                when (session.fileSystemType()) {
                    NativeBridge.FS_FAT32, NativeBridge.FS_EXFAT ->
                        SessionOpenResult.Success(session)
                    else -> {
                        session.close()
                        SessionOpenResult.UnsupportedFileSystem
                    }
                }
            }
            handle == NativeBridge.OPEN_WRONG_PASSWORD ->
                SessionOpenResult.WrongPassword
            handle == NativeBridge.OPEN_CORRUPT_HEADER -> SessionOpenResult.CorruptHeader
            handle == NativeBridge.OPEN_UNSUPPORTED_HEADER -> SessionOpenResult.UnsupportedHeader
            handle == NativeBridge.OPEN_INVALID_FORMAT -> SessionOpenResult.InvalidFormat
            else -> SessionOpenResult.IoError
        }
    }

    fun activate(session: ContainerSession) {
        require(session.isOpen) { "Cannot activate a closed container session" }
        active.getAndSet(session)?.takeIf { it !== session }?.close()
    }

    fun currentOrNull(): ContainerSession? = active.get()?.takeIf { it.isOpen }

    fun unmount() {
        active.getAndSet(null)?.close()
    }
}
