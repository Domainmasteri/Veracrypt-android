package io.veracrypt.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.util.Log
import android.webkit.MimeTypeMap
import io.veracrypt.android.corenative.NativeBridge
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
        val size = lookupEntrySize(requestedPath)
        result.newRow().apply {
            add(OpenableColumns.DISPLAY_NAME, requestedPath.substringAfterLast('/'))
            add(OpenableColumns.SIZE, size)
        }
        return result
    }

    override fun getType(uri: Uri): String {
        val requestedPath = requirePath(uri)
        val extension = requestedPath.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
            ?: "application/octet-stream"
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (!mode.startsWith("r")) {
            throw UnsupportedOperationException("Read-only provider")
        }
        val fd = VeraCryptDocumentsProvider.mountedFdOrNull()
            ?: throw IllegalStateException("No mounted container")
        val requestedPath = requirePath(uri)
        val pipes = ParcelFileDescriptor.createReliablePipe()
        val readEnd = pipes[0]
        val writeEnd = pipes[1]
        val expectedSize = lookupEntrySize(requestedPath)

        Thread {
            try {
                ParcelFileDescriptor.AutoCloseOutputStream(writeEnd).use { out ->
                    var offset = 0L
                    while (true) {
                        val remaining = expectedSize?.minus(offset)
                        val toRead = if (remaining != null && remaining > 0L) {
                            minOf(CHUNK_SIZE.toLong(), remaining).toInt()
                        } else {
                            CHUNK_SIZE
                        }
                        if (toRead <= 0) break
                        val chunk = NativeBridge.nativeReadFile(fd, requestedPath, offset, toRead)
                            ?: throw FileNotFoundException("Could not read $requestedPath")
                        if (chunk.isEmpty()) break
                        out.write(chunk)
                        offset += chunk.size
                        if (chunk.size < toRead) break
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stream $requestedPath", e)
            }
        }.apply {
            isDaemon = true
            name = "viewer-${requestedPath.substringAfterLast('/')}"
            start()
        }

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
        return path
    }

    private fun lookupEntrySize(path: String): Long? {
        val fd = VeraCryptDocumentsProvider.mountedFdOrNull() ?: return null
        val parent = parentPath(path)
        val entries = NativeBridge.nativeListDir(fd, parent) ?: return null
        return entries.firstOrNull { it.path == path }?.sizeBytes
    }

    private fun parentPath(path: String): String {
        if (path == "/") return "/"
        val trimmed = path.trimEnd('/')
        val idx = trimmed.lastIndexOf('/')
        if (idx <= 0) return "/"
        return trimmed.substring(0, idx)
    }
}
