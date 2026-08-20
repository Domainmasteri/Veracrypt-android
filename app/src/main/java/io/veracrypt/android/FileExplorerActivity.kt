package io.veracrypt.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
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
import io.veracrypt.android.corenative.ContainerSession
import io.veracrypt.android.databinding.ActivityFileExplorerBinding
import io.veracrypt.android.databinding.ItemExplorerEntryBinding
import io.veracrypt.android.providersaf.VeraCryptDocumentsProvider
import java.io.IOException
import java.text.DecimalFormat
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

private const val KEY_PENDING_EXPORT_PATH = "pending_export_folder_path"
private const val KEY_CURRENT_PATH = "current_path"

class FileExplorerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityFileExplorerBinding
    private val adapter = EntryAdapter()
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private var currentPath: String = "/"

    /** Holds the container path of the folder to be exported, across configuration changes. */
    private var pendingExportFolderPath: String? = null

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
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityFileExplorerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.listEntries.adapter = adapter
        binding.listEntries.emptyView = binding.tvEmpty
        binding.btnUp.setOnClickListener { navigateUp() }
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
        loadPath(savedInstanceState?.getString(KEY_CURRENT_PATH) ?: "/")
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_CURRENT_PATH, currentPath)
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
        val session = VeraCryptDocumentsProvider.mountedSessionOrNull() ?: run {
            finish()
            return
        }
        binding.progress.visibility = View.VISIBLE
        binding.tvCurrentPath.text = path
        binding.btnUp.isEnabled = path != "/"
        worker.execute {
            try {
                val listed = session.list(path)
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

    private fun showFolderOptions(entry: VolumeEntry) {
        AlertDialog.Builder(this)
            .setTitle(entry.name)
            .setItems(arrayOf(getString(R.string.explorer_export_folder))) { _, _ ->
                AlertDialog.Builder(this)
                    .setTitle(R.string.export_plaintext_title)
                    .setMessage(R.string.export_plaintext_warning)
                    .setPositiveButton(R.string.export_plaintext_continue) { _, _ ->
                        pendingExportFolderPath = entry.path
                        exportFolderLauncher.launch(null)
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            .show()
    }

    /**
     * Export [containerFolderPath] (and all its contents) from the container to [destTreeUri],
     * preserving the directory structure inside the destination.
     */
    private fun exportFolderToUri(containerFolderPath: String, destTreeUri: Uri) {
        val session = VeraCryptDocumentsProvider.mountedSessionOrNull() ?: run {
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
                exportContainerDirectory(session, containerFolderPath, rootDestUri, counts)

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
        session: ContainerSession,
        containerPath: String,
        destDirUri: Uri,
        counts: IntArray
    ) {
        val entries = session.list(containerPath) ?: return
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
                exportContainerDirectory(session, entry.path, subDirUri, counts)
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
                            val chunk = session.read(entry.path, offset, toRead)
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
    private fun openFile(entry: VolumeEntry) {
        val mime = resolveMime(entry.path)
        val isSupported = mime == "application/pdf" || mime.startsWith("image/") || mime.startsWith("text/")
        if (!isSupported) {
            Toast.makeText(this, getString(R.string.status_unsupported_preview), Toast.LENGTH_SHORT).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.preview_plaintext_title)
            .setMessage(R.string.preview_plaintext_warning)
            .setPositiveButton(R.string.preview_plaintext_continue) { _, _ ->
                launchExternalPreview(entry, mime)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun launchExternalPreview(entry: VolumeEntry, mime: String) {
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
