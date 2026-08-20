package io.veracrypt.android.providersaf

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.util.Log
import android.webkit.MimeTypeMap
import io.veracrypt.android.coreapi.VolumeEntry
import io.veracrypt.android.corenative.ContainerSession
import io.veracrypt.android.corenative.ContainerSessionManager
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "VeraCryptDocsProvider"

/**
 * Storage Access Framework [DocumentsProvider] for VeraCrypt containers.
 *
 * This provider exposes the read-only root directory of an opened VeraCrypt
 * container to Android clients that speak the SAF protocol.
 *
 * ## Lifecycle
 * 1. The host app opens a container through the native session manager.
 * 2. It calls [mount] to activate the opaque session for this provider.
 * 3. Android's document picker discovers the root via [queryRoots].
 * 4. Directory listings flow through [queryChildDocuments] via [ContainerSession].
 * 5. [unmount] closes the session after already accepted operations complete.
 */
class VeraCryptDocumentsProvider : DocumentsProvider() {

    companion object {
        /** MIME type used for files inside the container whose type is unknown. */
        const val MIME_TYPE_VERACRYPT = "application/octet-stream"

        /** Columns returned for each root. */
        private val DEFAULT_ROOT_PROJECTION = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_MIME_TYPES,
            Root.COLUMN_FLAGS,
            Root.COLUMN_ICON,
            Root.COLUMN_TITLE,
            Root.COLUMN_DOCUMENT_ID
        )

        /** Columns returned for each document (file or directory). */
        private val DEFAULT_DOCUMENT_PROJECTION = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_LAST_MODIFIED,
            Document.COLUMN_FLAGS,
            Document.COLUMN_SIZE
        )

        /** Synthetic document ID representing the root of the container file system. */
        private const val ROOT_DOCUMENT_ID = "/"
        private const val STREAM_CHUNK_SIZE = 64 * 1024
        private data class ActiveStream(
            val writeEnd: ParcelFileDescriptor,
            val thread: Thread
        )
        private val activeStreams = ConcurrentHashMap<Long, ActiveStream>()
        private val nextStreamId = AtomicLong(1L)

        /**
         * Register a successfully opened native session with this provider.
         */
        fun mount(session: ContainerSession) {
            ContainerSessionManager.activate(session)
            Log.i(TAG, "Container session mounted")
        }

        /**
         * Unregister and close the current container.
         * Safe to call even when no container is mounted.
         */
        fun unmount() {
            activeStreams.values.forEach { stream ->
                runCatching { stream.writeEnd.closeWithError("Container unmounted") }
                stream.thread.interrupt()
            }
            activeStreams.clear()
            ContainerSessionManager.unmount()
            Log.i(TAG, "Container unmounted")
        }

        /** Returns true when a container is currently mounted. */
        fun isMounted(): Boolean = ContainerSessionManager.currentOrNull() != null

        /** Returns a stable snapshot of the active session, or null when unmounted. */
        fun mountedSessionOrNull(): ContainerSession? = ContainerSessionManager.currentOrNull()
    }

    override fun onCreate(): Boolean {
        Log.d(TAG, "VeraCryptDocumentsProvider created")
        return true
    }

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION)
        if (!isMounted()) return result

        result.newRow().apply {
            add(Root.COLUMN_ROOT_ID,      "veracrypt-root")
            add(Root.COLUMN_FLAGS,        Root.FLAG_SUPPORTS_IS_CHILD)
            add(Root.COLUMN_TITLE,        "VeraCrypt Container")
            add(Root.COLUMN_DOCUMENT_ID,  ROOT_DOCUMENT_ID)
            add(Root.COLUMN_MIME_TYPES,   "*/*")
            add(Root.COLUMN_ICON,         android.R.drawable.ic_menu_more)
        }

        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val normalizedId = normalizeDocumentId(documentId)
        val session = mountedSessionOrNull()
            ?: throw java.io.FileNotFoundException("The mounted container session has expired")
        if (normalizedId == ROOT_DOCUMENT_ID) {
            addDocumentRow(result, normalizedId)
        } else {
            val entry = lookupEntry(session, normalizedId)
                ?: throw java.io.FileNotFoundException("Unknown document")
            addEntryRow(result, entry)
        }
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val session = mountedSessionOrNull()
            ?: throw java.io.FileNotFoundException("The mounted container session has expired")
        val normalizedParent = normalizeDocumentId(parentDocumentId)
        if (normalizedParent != ROOT_DOCUMENT_ID) {
            val parent = lookupEntry(session, normalizedParent)
                ?: throw java.io.FileNotFoundException("Unknown parent document")
            if (!parent.isDirectory) throw java.io.FileNotFoundException("Parent is not a directory")
        }
        val entries = runCatching { session.list(normalizedParent) }.getOrNull()
            ?: throw java.io.FileNotFoundException("Directory could not be read")
        for (entry in entries) {
            addEntryRow(result, entry)
        }

        return result
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        val session = mountedSessionOrNull()
        if (session == null) {
            throw IllegalStateException("No VeraCrypt container is currently mounted")
        }

        // Use the cached file size when available so we can terminate the loop exactly.
        val normalizedId = normalizeDocumentId(documentId)
        val entry = lookupEntry(session, normalizedId)
            ?: throw java.io.FileNotFoundException("Unknown document")
        if (entry.isDirectory) {
            throw UnsupportedOperationException("Directories cannot be opened as files")
        }
        val fileSize = entry.sizeBytes

        if (!mode.startsWith("r") || mode.contains("w") || mode.contains("+")) {
            throw UnsupportedOperationException("Write is not supported")
        }
        val pipes = ParcelFileDescriptor.createReliablePipe()
        val readEnd   = pipes[0]
        val writeEnd  = pipes[1]

        val streamId = nextStreamId.getAndIncrement()
        lateinit var thread: Thread
        lateinit var sessionCancellation: java.io.Closeable
        thread = Thread {
            try {
                val out = java.io.FileOutputStream(writeEnd.fileDescriptor)
                try {
                    var offset = 0L
                    while (true) {
                        if (signal?.isCanceled == true || Thread.currentThread().isInterrupted) {
                            throw java.io.InterruptedIOException("Read cancelled")
                        }

                        val toRead = minOf(STREAM_CHUNK_SIZE.toLong(), fileSize - offset).toInt()
                        if (toRead <= 0) break

                        val chunk = session.read(normalizedId, offset, toRead)
                            ?: throw java.io.IOException("Container read failed")
                        if (chunk.isEmpty()) break

                        out.write(chunk)
                        offset += chunk.size

                        if (chunk.size < toRead) break // native signalled EOF
                    }
                    out.flush()
                    writeEnd.close()
                } catch (error: Exception) {
                    runCatching { writeEnd.closeWithError(error.message ?: "Container read failed") }
                    throw error
                }
            } catch (e: Exception) {
                Log.w(TAG, "Document stream ended with an error")
            } finally {
                activeStreams.remove(streamId)
                sessionCancellation.close()
            }
        }
        thread.isDaemon = true
        thread.name = "veracrypt-document-stream"
        sessionCancellation = session.onClose {
            runCatching { writeEnd.closeWithError("Container unmounted") }
            thread.interrupt()
        }
        activeStreams[streamId] = ActiveStream(writeEnd, thread)
        signal?.setOnCancelListener {
            runCatching { writeEnd.closeWithError("Read cancelled") }
            thread.interrupt()
        }
        thread.start()

        return readEnd
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Add a row built from a cached [VolumeEntry]. */
    private fun addEntryRow(cursor: MatrixCursor, entry: VolumeEntry) {
        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID,   entry.path)
            add(Document.COLUMN_MIME_TYPE,
                if (entry.isDirectory) Document.MIME_TYPE_DIR else mimeTypeFor(entry.name))
            add(Document.COLUMN_DISPLAY_NAME,  entry.name)
            add(Document.COLUMN_LAST_MODIFIED, entry.lastModifiedMs.takeIf { it > 0L })
            add(
                Document.COLUMN_FLAGS,
                0
            )
            add(Document.COLUMN_SIZE,
                if (entry.isDirectory) null else entry.sizeBytes)
        }
    }

    /** Fallback row for documents not yet in the cache (e.g. the root itself). */
    private fun addDocumentRow(cursor: MatrixCursor, documentId: String) {
        val isRoot = documentId == ROOT_DOCUMENT_ID
        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID,  documentId)
            add(Document.COLUMN_MIME_TYPE,
                if (isRoot) Document.MIME_TYPE_DIR else MIME_TYPE_VERACRYPT)
            add(Document.COLUMN_DISPLAY_NAME,
                if (isRoot) "VeraCrypt Container" else documentId.substringAfterLast('/'))
            add(Document.COLUMN_LAST_MODIFIED, null)
            add(Document.COLUMN_FLAGS,         0)
            add(Document.COLUMN_SIZE,          null)
        }
    }

    private fun lookupEntry(session: ContainerSession, documentId: String): VolumeEntry? {
        if (documentId == ROOT_DOCUMENT_ID) return null
        val parent = documentId.substringBeforeLast('/', "").ifEmpty { "/" }
        return runCatching { session.list(parent) }.getOrNull()
            ?.firstOrNull { it.path == documentId }
    }

    private fun normalizeDocumentId(documentId: String): String {
        if (documentId == ROOT_DOCUMENT_ID) return documentId
        if (!documentId.startsWith('/') || documentId.endsWith('/') ||
            documentId.length > 4096) {
            throw java.io.FileNotFoundException("Malformed document ID")
        }
        val parts = documentId.substring(1).split('/')
        if (parts.any { it.isEmpty() || it == "." || it == ".." }) {
            throw java.io.FileNotFoundException("Malformed document ID")
        }
        return "/" + parts.joinToString("/")
    }

    private fun mimeTypeFor(name: String): String {
        val extension = name.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
            ?: MIME_TYPE_VERACRYPT
    }

}
