package io.veracrypt.android.providersaf

import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.util.Log
import io.veracrypt.android.coreapi.ContainerReader

private const val TAG = "VeraCryptDocsProvider"

/**
 * Storage Access Framework [DocumentsProvider] skeleton for VeraCrypt containers.
 *
 * This provider exposes the (read-only) file system inside an opened VeraCrypt
 * container to any Android picker or file-manager that speaks the SAF protocol.
 *
 * ## Lifecycle
 * 1. The host app opens a container via [io.veracrypt.android.corenative.NativeBridge].
 * 2. It calls [mount] to register the [ContainerReader] with this provider.
 * 3. Android's document picker discovers the root via [queryRoots].
 * 4. Directory listings and file reads flow through [queryChildDocuments] / [openDocument].
 * 5. The host app calls [unmount] when the user closes the container.
 *
 * NOTE: Full implementation (cursor population, read streams) is deferred to a later milestone.
 */
class VeraCryptDocumentsProvider : DocumentsProvider() {

    companion object {
        /** MIME type used for VeraCrypt container files. */
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

        @Volatile
        private var currentReader: ContainerReader? = null

        /**
         * Register a successfully opened [ContainerReader] with this provider.
         * Subsequent SAF queries will be answered using this reader.
         */
        fun mount(reader: ContainerReader) {
            currentReader = reader
            Log.i(TAG, "Container mounted")
        }

        /**
         * Unregister and close the current [ContainerReader].
         */
        fun unmount() {
            currentReader?.close()
            currentReader = null
            Log.i(TAG, "Container unmounted")
        }
    }

    override fun onCreate(): Boolean {
        Log.d(TAG, "VeraCryptDocumentsProvider created")
        return true
    }

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION)
        val reader = currentReader ?: return result

        result.newRow().apply {
            add(Root.COLUMN_ROOT_ID, "veracrypt-root")
            add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_IS_CHILD)
            add(Root.COLUMN_TITLE, "VeraCrypt Container")
            add(Root.COLUMN_DOCUMENT_ID, ROOT_DOCUMENT_ID)
            add(Root.COLUMN_MIME_TYPES, "*/*")
            add(Root.COLUMN_ICON, android.R.drawable.ic_menu_more)
        }

        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        addDocumentRow(result, documentId)
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val reader = currentReader ?: return result

        try {
            val entries = reader.list(parentDocumentId)
            for (entry in entries) {
                result.newRow().apply {
                    add(Document.COLUMN_DOCUMENT_ID, entry.path)
                    add(
                        Document.COLUMN_MIME_TYPE,
                        if (entry.isDirectory) Document.MIME_TYPE_DIR else MIME_TYPE_VERACRYPT
                    )
                    add(Document.COLUMN_DISPLAY_NAME, entry.name)
                    add(Document.COLUMN_LAST_MODIFIED, entry.lastModifiedMs)
                    add(Document.COLUMN_FLAGS, 0)
                    add(Document.COLUMN_SIZE, entry.sizeBytes)
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
        // Read-only mode only; write access is intentionally unsupported.
        if (mode != "r") {
            throw UnsupportedOperationException("VeraCryptDocumentsProvider is read-only")
        }
        // TODO: return a ParcelFileDescriptor backed by NativeBridge reads
        throw UnsupportedOperationException("openDocument not yet implemented")
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun addDocumentRow(cursor: MatrixCursor, documentId: String) {
        val isRoot = documentId == ROOT_DOCUMENT_ID
        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID, documentId)
            add(Document.COLUMN_MIME_TYPE, if (isRoot) Document.MIME_TYPE_DIR else MIME_TYPE_VERACRYPT)
            add(Document.COLUMN_DISPLAY_NAME, if (isRoot) "VeraCrypt Container" else documentId.substringAfterLast('/'))
            add(Document.COLUMN_LAST_MODIFIED, null)
            add(Document.COLUMN_FLAGS, 0)
            add(Document.COLUMN_SIZE, null)
        }
    }
}
