package io.veracrypt.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.MimeTypeMap
import android.widget.BaseAdapter
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.addCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import io.veracrypt.android.coreapi.VolumeEntry
import io.veracrypt.android.corenative.NativeBridge
import io.veracrypt.android.databinding.ActivityFileExplorerBinding
import io.veracrypt.android.databinding.ItemExplorerEntryBinding
import io.veracrypt.android.providersaf.VeraCryptDocumentsProvider
import java.io.IOException
import java.text.DecimalFormat
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

private const val KEY_PENDING_EXPORT_PATH = "pending_export_folder_path"

class FileExplorerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityFileExplorerBinding
    private val adapter = EntryAdapter()
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private var currentPath: String = "/"

    /** Holds the container path of the folder to be exported, across configuration changes. */
    private var pendingExportFolderPath: String? = null

    private val importDocumentLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) importFileFromUri(uri)
        }

    private val importFolderLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) importFolderFromUri(uri)
        }

    private val exportFolderLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) {
                val path = pendingExportFolderPath ?: return@registerForActivityResult
                pendingExportFolderPath = null
                exportFolderToUri(path, uri)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileExplorerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.listEntries.adapter = adapter
        binding.listEntries.emptyView = binding.tvEmpty
        binding.btnUp.setOnClickListener { navigateUp() }
        binding.fabImport.setOnClickListener { showImportMenu() }
        binding.listEntries.setOnItemClickListener { _, _, position, _ ->
            val entry = adapter.getItem(position)
            if (entry.isDirectory) {
                loadPath(entry.path)
            } else {
                openFile(entry)
            }
        }
        binding.listEntries.setOnItemLongClickListener { _, _, position, _ ->
            val entry = adapter.getItem(position)
            if (entry.isDirectory) {
                showFolderOptions(entry)
                true
            } else {
                false
            }
        }

        onBackPressedDispatcher.addCallback(this) {
            if (currentPath != "/") navigateUp() else finish()
        }

        if (!VeraCryptDocumentsProvider.isMounted()) {
            finish()
            return
        }
        loadPath("/")
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingExportFolderPath?.let { outState.putString(KEY_PENDING_EXPORT_PATH, it) }
    }

    override fun onRestoreInstanceState(savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        pendingExportFolderPath = savedInstanceState.getString(KEY_PENDING_EXPORT_PATH)
    }

    override fun onDestroy() {
        super.onDestroy()
        worker.shutdownNow()
    }

    private fun navigateUp() {
        if (currentPath == "/") {
            finish()
            return
        }
        loadPath(parentPath(currentPath))
    }

    private fun loadPath(path: String) {
        val fd = VeraCryptDocumentsProvider.mountedFdOrNull() ?: run {
            finish()
            return
        }
        binding.progress.visibility = View.VISIBLE
        binding.tvCurrentPath.text = path
        binding.btnUp.isEnabled = path != "/"
        worker.execute {
            try {
                val listed = NativeBridge.nativeListDir(fd, path)
                    ?.sortedWith(compareBy<VolumeEntry> { !it.isDirectory }.thenBy { it.name.lowercase() })
                    ?: throw IllegalStateException("nativeListDir returned null for $path")

                runOnUiThread {
                    currentPath = path
                    adapter.submit(listed)
                    binding.progress.visibility = View.GONE
                }
            } catch (e: Exception) {
                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    Toast.makeText(
                        this,
                        e.message ?: e.toString(),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun showImportMenu() {
        AlertDialog.Builder(this)
            .setItems(
                arrayOf(
                    getString(R.string.explorer_import_file),
                    getString(R.string.explorer_import_folder)
                )
            ) { _, which ->
                when (which) {
                    0 -> importDocumentLauncher.launch(arrayOf("*/*"))
                    1 -> importFolderLauncher.launch(null)
                }
            }
            .show()
    }

    private fun showFolderOptions(entry: VolumeEntry) {
        AlertDialog.Builder(this)
            .setTitle(entry.name)
            .setItems(arrayOf(getString(R.string.explorer_export_folder))) { _, _ ->
                pendingExportFolderPath = entry.path
                exportFolderLauncher.launch(null)
            }
            .show()
    }

    private fun importFileFromUri(uri: Uri) {
        val fd = VeraCryptDocumentsProvider.mountedFdOrNull() ?: run {
            finish()
            return
        }
        val fileName = resolveImportName(uri)
        val destinationPath = joinPath(currentPath, fileName)

        binding.progress.visibility = View.VISIBLE
        Toast.makeText(this, getString(R.string.explorer_importing), Toast.LENGTH_SHORT).show()

        worker.execute {
            try {
                contentResolver.openInputStream(uri)?.use { input ->
                    val buffer = ByteArray(65536)
                    var offset = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        val chunk = if (read == buffer.size) buffer else buffer.copyOf(read)
                        val written = NativeBridge.nativeWriteFile(fd, destinationPath, offset, chunk)
                        if (written <= 0) {
                            throw IOException("nativeWriteFile failed ($written) for $destinationPath")
                        }
                        offset += written
                    }
                } ?: throw IOException("Unable to open input stream for $uri")

                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    Toast.makeText(
                        this,
                        getString(R.string.explorer_import_done, fileName),
                        Toast.LENGTH_SHORT
                    ).show()
                    loadPath(currentPath)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    Toast.makeText(
                        this,
                        e.message ?: e.toString(),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun resolveImportName(uri: Uri): String {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) {
                val name = cursor.getString(index)
                if (!name.isNullOrBlank()) return name
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() }
            ?: "imported_file"
    }

    /**
     * Import all files from [treeUri] (recursively) into [currentPath] inside the container.
     * Directory structure from the source is flattened – all files are placed directly in
     * [currentPath]. Files with the same name overwrite each other.
     */
    private fun importFolderFromUri(treeUri: Uri) {
        val fd = VeraCryptDocumentsProvider.mountedFdOrNull() ?: run {
            finish()
            return
        }

        binding.progress.visibility = View.VISIBLE
        Toast.makeText(this, getString(R.string.explorer_importing_folder), Toast.LENGTH_SHORT).show()

        worker.execute {
            val counts = IntArray(2) // [0] = imported, [1] = failed
            try {
                val files = collectDocumentTreeFiles(treeUri)
                for ((displayName, fileUri) in files) {
                    val destinationPath = joinPath(currentPath, displayName)
                    try {
                        contentResolver.openInputStream(fileUri)?.use { input ->
                            val buffer = ByteArray(65536)
                            var offset = 0L
                            while (true) {
                                val read = input.read(buffer)
                                if (read <= 0) break
                                val chunk = if (read == buffer.size) buffer else buffer.copyOf(read)
                                val written = NativeBridge.nativeWriteFile(fd, destinationPath, offset, chunk)
                                if (written <= 0) throw IOException("nativeWriteFile failed ($written)")
                                offset += written
                            }
                        } ?: throw IOException("Unable to open input stream for $fileUri")
                        counts[0]++
                    } catch (_: Exception) {
                        counts[1]++
                    }
                }

                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    val msg = if (counts[1] == 0) {
                        getString(R.string.explorer_import_folder_done, counts[0])
                    } else {
                        getString(R.string.explorer_import_folder_partial, counts[0], counts[1])
                    }
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                    loadPath(currentPath)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    Toast.makeText(this, e.message ?: e.toString(), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    /**
     * Recursively collect all file (non-directory) entries from a document tree.
     * Returns a list of (displayName, fileUri) pairs. Directory structure is flattened –
     * only the immediate file name is returned as the display name.
     */
    private fun collectDocumentTreeFiles(treeUri: Uri): List<Pair<String, Uri>> {
        val result = mutableListOf<Pair<String, Uri>>()
        val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
        collectFromDocumentChildren(treeUri, rootDocId, result)
        return result
    }

    private fun collectFromDocumentChildren(
        treeUri: Uri,
        parentDocId: String,
        result: MutableList<Pair<String, Uri>>
    ) {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocId)
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        )?.use { cursor ->
            val idCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            while (cursor.moveToNext()) {
                val docId = cursor.getString(idCol) ?: continue
                val name = cursor.getString(nameCol) ?: continue
                val mime = cursor.getString(mimeCol) ?: continue
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    collectFromDocumentChildren(treeUri, docId, result)
                } else {
                    val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                    result.add(Pair(name, fileUri))
                }
            }
        }
    }

    /**
     * Export [containerFolderPath] (and all its contents) from the container to [destTreeUri],
     * preserving the directory structure inside the destination.
     */
    private fun exportFolderToUri(containerFolderPath: String, destTreeUri: Uri) {
        val fd = VeraCryptDocumentsProvider.mountedFdOrNull() ?: run {
            finish()
            return
        }

        binding.progress.visibility = View.VISIBLE
        Toast.makeText(this, getString(R.string.explorer_exporting_folder), Toast.LENGTH_SHORT).show()

        worker.execute {
            val counts = IntArray(2) // [0] = exported, [1] = failed
            try {
                val rootDocId = DocumentsContract.getTreeDocumentId(destTreeUri)
                val rootDestUri = DocumentsContract.buildDocumentUriUsingTree(destTreeUri, rootDocId)
                exportContainerDirectory(fd, containerFolderPath, rootDestUri, counts)

                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    val msg = if (counts[1] == 0) {
                        getString(R.string.explorer_export_folder_done, counts[0])
                    } else {
                        getString(R.string.explorer_export_folder_partial, counts[0], counts[1])
                    }
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    binding.progress.visibility = View.GONE
                    Toast.makeText(this, e.message ?: e.toString(), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    /**
     * Recursively export all entries under [containerPath] into [destDirUri] on the device,
     * recreating the directory hierarchy via [DocumentsContract.createDocument].
     */
    private fun exportContainerDirectory(
        fd: Int,
        containerPath: String,
        destDirUri: Uri,
        counts: IntArray
    ) {
        val entries = NativeBridge.nativeListDir(fd, containerPath) ?: return
        for (entry in entries) {
            if (entry.isDirectory) {
                val subDirUri = try {
                    DocumentsContract.createDocument(
                        contentResolver,
                        destDirUri,
                        DocumentsContract.Document.MIME_TYPE_DIR,
                        entry.name
                    )
                } catch (_: Exception) {
                    null
                } ?: continue
                exportContainerDirectory(fd, entry.path, subDirUri, counts)
            } else {
                try {
                    val mime = resolveMime(entry.path)
                    val fileUri = DocumentsContract.createDocument(
                        contentResolver,
                        destDirUri,
                        mime,
                        entry.name
                    ) ?: throw IOException("Could not create document for ${entry.name}")

                    contentResolver.openOutputStream(fileUri)?.use { output ->
                        val chunkSize = 4 * 1024 * 1024 // native cap is 4 MiB
                        var offset = 0L
                        while (offset < entry.sizeBytes) {
                            val toRead = (entry.sizeBytes - offset).coerceAtMost(chunkSize.toLong()).toInt()
                            val chunk = NativeBridge.nativeReadFile(fd, entry.path, offset, toRead)
                                ?: throw IOException("nativeReadFile returned null for ${entry.path}")
                            if (chunk.isEmpty()) break
                            output.write(chunk)
                            offset += chunk.size
                        }
                    } ?: throw IOException("Could not open output stream for ${entry.name}")
                    counts[0]++
                } catch (_: Exception) {
                    counts[1]++
                }
            }
        }
    }


    private fun joinPath(base: String, name: String): String {
        val cleanName = name.substringAfterLast('/').ifBlank { "imported_file" }
        return if (base == "/") "/$cleanName" else "${base.trimEnd('/')}/$cleanName"
    }

    private fun openFile(entry: VolumeEntry) {
        val mime = resolveMime(entry.path)
        val isSupported = mime == "application/pdf" || mime.startsWith("image/") || mime.startsWith("text/")
        if (!isSupported) {
            Toast.makeText(this, getString(R.string.status_unsupported_preview), Toast.LENGTH_SHORT).show()
            return
        }

        val uri: Uri = ContainerViewerProvider.buildUri(entry.path)
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, mime)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY)

        try {
            startActivity(intent)
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, getString(R.string.status_no_viewer_app), Toast.LENGTH_SHORT).show()
        }
    }

    private fun resolveMime(path: String): String {
        val ext = path.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
    }

    private fun parentPath(path: String): String {
        if (path == "/") return "/"
        val trimmed = path.trimEnd('/')
        val index = trimmed.lastIndexOf('/')
        if (index <= 0) return "/"
        return trimmed.substring(0, index)
    }
}

private class EntryAdapter : BaseAdapter() {
    private val entries = mutableListOf<VolumeEntry>()
    private val sizeFormat = DecimalFormat("#.##")

    fun submit(newEntries: List<VolumeEntry>) {
        entries.clear()
        entries.addAll(newEntries)
        notifyDataSetChanged()
    }

    override fun getCount(): Int = entries.size
    override fun getItem(position: Int): VolumeEntry = entries[position]
    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val holder: ItemExplorerEntryBinding
        val root: View
        if (convertView == null) {
            holder = ItemExplorerEntryBinding.inflate(LayoutInflater.from(parent.context), parent, false)
            root = holder.root
            root.tag = holder
        } else {
            root = convertView
            holder = convertView.tag as ItemExplorerEntryBinding
        }

        val entry = getItem(position)
        holder.ivIcon.setImageResource(
            if (entry.isDirectory) android.R.drawable.ic_menu_agenda else android.R.drawable.ic_menu_save
        )
        holder.tvName.text = entry.name
        holder.tvMeta.text = if (entry.isDirectory) {
            holder.root.context.getString(R.string.file_meta_folder)
        } else {
            humanSize(entry.sizeBytes)
        }
        return root
    }

    private fun humanSize(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        if (bytes < 1024 * 1024) return "${sizeFormat.format(bytes / 1024.0)} KB"
        if (bytes < 1024L * 1024L * 1024L) return "${sizeFormat.format(bytes / (1024.0 * 1024.0))} MB"
        return "${sizeFormat.format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
    }
}
