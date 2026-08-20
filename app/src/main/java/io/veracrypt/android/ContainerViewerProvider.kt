package io.veracrypt.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.util.Log
import android.webkit.MimeTypeMap
import io.veracrypt.android.providersaf.VeraCryptDocumentsProvider
import java.io.FileNotFoundException

private const val TAG = "ContainerViewerProvider"

class ContainerViewerProvider : ContentProvider() {

    companion object {
        const val AUTHORITY = "io.veracrypt.android.viewer"
        private const val CHUNK_SIZE = 64 * 1024

        fun buildUri(path: String): Uri =
            Uri.Builder()
                .scheme("content")
                .authority(AUTHORITY)
                .appendPath("entry")
                .appendQueryParameter("path", path)
                .build()
    }

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val requestedPath = requirePath(uri)
        val result = MatrixCursor(
            projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        )
        val session = VeraCryptDocumentsProvider.mountedSessionOrNull()
            ?: throw FileNotFoundException("No mounted container")
        val entry = lookupEntry(session, requestedPath)
            ?: throw FileNotFoundException("Unknown container entry")
        if (entry.isDirectory) throw FileNotFoundException("Entry is a directory")
        result.newRow().apply {
            add(OpenableColumns.DISPLAY_NAME, entry.name)
            add(OpenableColumns.SIZE, entry.sizeBytes)
        }
        return result
    }

    override fun getType(uri: Uri): String {
        val requestedPath = requirePath(uri)
        val session = VeraCryptDocumentsProvider.mountedSessionOrNull()
            ?: throw FileNotFoundException("No mounted container")
        val entry = lookupEntry(session, requestedPath)
            ?: throw FileNotFoundException("Unknown container entry")
        if (entry.isDirectory) throw FileNotFoundException("Entry is a directory")
        val extension = entry.name.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
            ?: "application/octet-stream"
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor =
        openReadPipe(uri, mode, null)

    override fun openFile(
        uri: Uri,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor = openReadPipe(uri, mode, signal)

    private fun openReadPipe(
        uri: Uri,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        if (!mode.startsWith("r") || mode.contains('w') || mode.contains('+')) {
            throw UnsupportedOperationException("Read-only provider")
        }
        val session = VeraCryptDocumentsProvider.mountedSessionOrNull()
            ?: throw IllegalStateException("No mounted container")
        val requestedPath = requirePath(uri)
        val entry = lookupEntry(session, requestedPath)
            ?: throw FileNotFoundException("Unknown container entry")
        if (entry.isDirectory) throw FileNotFoundException("Entry is a directory")
        val pipes = ParcelFileDescriptor.createReliablePipe()
        val readEnd = pipes[0]
        val writeEnd = pipes[1]
        val expectedSize = entry.sizeBytes
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
                        val remaining = expectedSize.minus(offset)
                        val toRead = if (remaining > 0L) {
                            minOf(CHUNK_SIZE.toLong(), remaining).toInt()
                        } else {
                            0
                        }
                        if (toRead <= 0) break
                        val chunk = session.read(requestedPath, offset, toRead)
                            ?: throw FileNotFoundException("Could not read $requestedPath")
                        if (chunk.isEmpty()) break
                        out.write(chunk)
                        offset += chunk.size
                        if (chunk.size < toRead) break
                    }
                    out.flush()
                    writeEnd.close()
                } catch (error: Exception) {
                    runCatching { writeEnd.closeWithError(error.message ?: "Container read failed") }
                    throw error
                }
            } catch (e: Exception) {
                Log.w(TAG, "Viewer stream ended with an error")
            } finally {
                signal?.setOnCancelListener(null)
                sessionCancellation.close()
            }
        }.apply {
            isDaemon = true
            name = "viewer-${requestedPath.substringAfterLast('/')}"
        }
        sessionCancellation = session.onClose {
            runCatching { writeEnd.closeWithError("Container unmounted") }
            thread.interrupt()
        }
        signal?.setOnCancelListener {
            runCatching { writeEnd.closeWithError("Read cancelled") }
            thread.interrupt()
        }
        thread.start()

        return readEnd
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0

    private fun requirePath(uri: Uri): String {
        val path = uri.getQueryParameter("path")
        require(!path.isNullOrBlank()) { "Missing path query parameter" }
        require(path.startsWith('/') && !path.endsWith('/') && path.length <= 4096) {
            "Malformed container path"
        }
        require(path.substring(1).split('/').none { it.isEmpty() || it == "." || it == ".." }) {
            "Malformed container path"
        }
        return path
    }

    private fun lookupEntry(
        session: io.veracrypt.android.corenative.ContainerSession,
        path: String
    ): io.veracrypt.android.coreapi.VolumeEntry? {
        val parent = parentPath(path)
        val entries = runCatching { session.list(parent) }.getOrNull() ?: return null
        return entries.firstOrNull { it.path == path }
    }

    private fun parentPath(path: String): String {
        if (path == "/") return "/"
        val trimmed = path.trimEnd('/')
        val idx = trimmed.lastIndexOf('/')
        if (idx <= 0) return "/"
        return trimmed.substring(0, idx)
    }
}
