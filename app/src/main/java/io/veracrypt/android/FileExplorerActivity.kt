package io.veracrypt.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.MimeTypeMap
import android.widget.BaseAdapter
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.addCallback
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

class FileExplorerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityFileExplorerBinding
    private val adapter = EntryAdapter()
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private var currentPath: String = "/"
    private val importDocumentLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                importFileFromUri(uri)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileExplorerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.listEntries.adapter = adapter
        binding.listEntries.emptyView = binding.tvEmpty
        binding.btnUp.setOnClickListener { navigateUp() }
        binding.fabImport.setOnClickListener { launchImportPicker() }
        binding.listEntries.setOnItemClickListener { _, _, position, _ ->
            val entry = adapter.getItem(position)
            if (entry.isDirectory) {
                loadPath(entry.path)
            } else {
                openFile(entry)
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

    private fun launchImportPicker() {
        importDocumentLauncher.launch(arrayOf("*/*"))
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
