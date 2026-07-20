package io.veracrypt.android.providersaf

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.util.Log
import io.veracrypt.android.coreapi.VolumeEntry
import io.veracrypt.android.corenative.NativeBridge
import java.util.concurrent.ConcurrentHashMap

private const val TAG = "VeraCryptDocsProvider"

/**
 * Storage Access Framework [DocumentsProvider] for VeraCrypt containers.
 *
 * This provider exposes the (read-only) file system inside an opened VeraCrypt
 * container to any Android picker or file-manager that speaks the SAF protocol.
 *
 * ## Lifecycle
 * 1. The host app opens a container via [NativeBridge.nativeParseHeader].
 * 2. It calls [mount] to register the open [ParcelFileDescriptor] with this provider.
 * 3. Android's document picker discovers the root via [queryRoots].
 * 4. Directory listings flow through [queryChildDocuments] via [NativeBridge.nativeListDir].
 * 5. The host app calls [unmount] when the user closes the container, which closes the fd.
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

        /** The open [ParcelFileDescriptor] passed to [mount].  Owned by this provider. */
        @Volatile
        private var mountedPfd: ParcelFileDescriptor? = null

        /**
         * Raw int file descriptor extracted from [mountedPfd].
         * -1 when no container is mounted.
         */
        @Volatile
        private var mountedFd: Int = -1

        /**
         * Cache of [VolumeEntry] objects by document-path, populated lazily by
         * [queryChildDocuments] and consumed by [queryDocument].
         */
        private val entryCache = ConcurrentHashMap<String, VolumeEntry>()

        /**
         * Register a successfully opened container with this provider.
         *
         * The provider takes **ownership** of [pfd] and will close it in [unmount].
         * The caller must not close [pfd] after calling this function.
         *
         * @param pfd Open, readable [ParcelFileDescriptor] of the VeraCrypt container.
         *            [NativeBridge.nativeParseHeader] must have returned 0 for this fd.
         */
        fun mount(pfd: ParcelFileDescriptor) {
            // Close any previously mounted container before mounting the new one
            try { mountedPfd?.close() } catch (_: Exception) {}
            mountedPfd = pfd
            mountedFd  = pfd.fd
            entryCache.clear()
            Log.i(TAG, "Container mounted fd=${pfd.fd}")
        }

        /**
         * Unregister and close the current container.
         * Safe to call even when no container is mounted.
         */
        fun unmount() {
            try { mountedPfd?.close() } catch (_: Exception) {}
            mountedPfd = null
            mountedFd  = -1
            entryCache.clear()
            Log.i(TAG, "Container unmounted")
        }
    }

    override fun onCreate(): Boolean {
        Log.d(TAG, "VeraCryptDocumentsProvider created")
        return true
    }

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION)
        if (mountedFd < 0) return result

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
        val cached = entryCache[documentId]
        if (cached != null) {
            addEntryRow(result, cached)
        } else {
            addDocumentRow(result, documentId)
        }
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val fd = mountedFd
        if (fd < 0) return result

        try {
            val entries = NativeBridge.nativeListDir(fd, parentDocumentId) ?: return result
            for (entry in entries) {
                entryCache[entry.path] = entry
                result.newRow().apply {
                    add(Document.COLUMN_DOCUMENT_ID,   entry.path)
                    add(Document.COLUMN_MIME_TYPE,
                        if (entry.isDirectory) Document.MIME_TYPE_DIR else MIME_TYPE_VERACRYPT)
                    add(Document.COLUMN_DISPLAY_NAME,  entry.name)
                    add(Document.COLUMN_LAST_MODIFIED, entry.lastModifiedMs.takeIf { it > 0L })
                    add(Document.COLUMN_FLAGS,         0)
                    add(Document.COLUMN_SIZE,
                        if (entry.isDirectory) null else entry.sizeBytes)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error listing children of $parentDocumentId", e)
        }

        return result
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        if (mode != "r") {
            throw UnsupportedOperationException("VeraCryptDocumentsProvider is read-only")
        }
        // TODO: return a ParcelFileDescriptor backed by NativeBridge reads
        throw UnsupportedOperationException("openDocument not yet implemented")
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Add a row built from a cached [VolumeEntry]. */
    private fun addEntryRow(cursor: MatrixCursor, entry: VolumeEntry) {
        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID,   entry.path)
            add(Document.COLUMN_MIME_TYPE,
                if (entry.isDirectory) Document.MIME_TYPE_DIR else MIME_TYPE_VERACRYPT)
            add(Document.COLUMN_DISPLAY_NAME,  entry.name)
            add(Document.COLUMN_LAST_MODIFIED, entry.lastModifiedMs.takeIf { it > 0L })
            add(Document.COLUMN_FLAGS,         0)
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
}

