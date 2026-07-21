package io.veracrypt.android

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.text.InputType
import android.util.Log
import android.view.LayoutInflater
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Spinner
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import io.veracrypt.android.corenative.NativeBridge
import io.veracrypt.android.databinding.ActivityMainBinding
import io.veracrypt.android.providersaf.VeraCryptDocumentsProvider

private const val TAG = "MainActivity"

/**
 * Main entry point of the VeraCrypt Android read-only MVP.
 *
 * Allows the user to pick a VeraCrypt container file via the Storage Access
 * Framework, prompts for the password, then passes the raw file descriptor and
 * password to the native bridge for header decryption.
 *
 * On success the [ParcelFileDescriptor] is kept open and transferred to
 * [VeraCryptDocumentsProvider] so that the SAF file browser can list entries
 * inside the container.  The PFD is closed when [onDestroy] is called or when
 * a new container is successfully opened.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    /**
     * The PFD of the currently mounted container.
     * Ownership is shared with [VeraCryptDocumentsProvider]; it is closed by
     * [VeraCryptDocumentsProvider.unmount] (called from [onDestroy]).
     */
    private var containerPfd: ParcelFileDescriptor? = null

    private val pickContainer = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            onContainerSelected(uri)
        }
    }

    private val createContainer = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        if (uri != null) {
            showCreateContainerDialog(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnOpenContainer.setOnClickListener {
            pickContainer.launch(arrayOf("*/*"))
        }
        binding.btnCreateContainer.setOnClickListener {
            createContainer.launch("new-container.vc")
        }
        binding.btnRootMount.setOnClickListener {
            showRootMountDialog()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // unmount() closes the PFD owned by the provider; clear our reference.
        VeraCryptDocumentsProvider.unmount()
        containerPfd = null
    }

    private fun onContainerSelected(uri: Uri) {
        binding.tvStatus.text = getString(R.string.status_selected, uri.lastPathSegment ?: uri.toString())
        showPasswordDialog(uri)
    }

    private fun showPasswordDialog(uri: Uri) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = getString(R.string.password_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.password_dialog_title)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val password = input.text.toString().toByteArray(Charsets.UTF_8)
                openContainerWithPassword(uri, password)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun openContainerWithPassword(uri: Uri, password: ByteArray) {
        binding.tvStatus.text = getString(R.string.status_opening)
        binding.btnOpenContainer.isEnabled = false

        Thread {
            var pfd: ParcelFileDescriptor? = null
            var result = Int.MIN_VALUE

            try {
                // Open read-write so that nativeWriteFile can allocate FAT clusters
                // and write directory entries via vc_write_sector.  Fall back to
                // read-only for containers on read-only storage (e.g. a network share
                // or a file opened from a read-only URI).
                pfd = try {
                    contentResolver.openFileDescriptor(uri, "rw")
                } catch (_: Exception) {
                    Log.w(TAG, "Could not open container rw; falling back to r (writes will fail)")
                    contentResolver.openFileDescriptor(uri, "r")
                }
                if (pfd != null) {
                    result = NativeBridge.nativeParseHeader(pfd.fd, password)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error opening container", e)
                pfd?.close()
                pfd = null
            }

            // On failure, close the PFD immediately; on success hand it off to the provider.
            if (result != 0) {
                pfd?.close()
                pfd = null
            }

            val successPfd = pfd // non-null only when result == 0

            runOnUiThread {
                binding.btnOpenContainer.isEnabled = true

                if (successPfd != null) {
                    // Transfer PFD ownership to the provider (closes any previously mounted one)
                    containerPfd = successPfd
                    VeraCryptDocumentsProvider.mount(successPfd)
                    binding.tvStatus.text = getString(R.string.status_mounted)
                    startActivity(Intent(this, FileExplorerActivity::class.java))
                } else {
                    binding.tvStatus.text = when (result) {
                        -1            -> getString(R.string.status_wrong_password)
                        Int.MIN_VALUE -> getString(R.string.status_error_open)
                        else          -> getString(R.string.status_error_format)
                    }
                }
            }
        }.start()
    }

    private fun showCreateContainerDialog(uri: Uri) {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_create_container, null)
        val sizeInput = dialogView.findViewById<EditText>(R.id.et_size_value).apply {
            setText("128")
        }
        val passwordInput = dialogView.findViewById<EditText>(R.id.et_create_password)
        val unitSpinner = dialogView.findViewById<Spinner>(R.id.spinner_size_unit)
        val fsSpinner = dialogView.findViewById<Spinner>(R.id.spinner_filesystem)

        unitSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            resources.getStringArray(R.array.create_size_units)
        )
        fsSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            resources.getStringArray(R.array.create_fs_options)
        )

        AlertDialog.Builder(this)
            .setTitle(R.string.create_dialog_title)
            .setView(dialogView)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val sizeValue = sizeInput.text.toString().toDoubleOrNull()
                if (sizeValue == null || sizeValue <= 0.0) {
                    binding.tvStatus.text = getString(R.string.status_invalid_size)
                    return@setPositiveButton
                }
                val password = passwordInput.text.toString().toByteArray(Charsets.UTF_8)
                val unitMultiplier = when (unitSpinner.selectedItemPosition) {
                    0 -> 1024L * 1024L
                    1 -> 1024L * 1024L * 1024L
                    else -> {
                        binding.tvStatus.text = getString(R.string.status_invalid_size)
                        return@setPositiveButton
                    }
                }
                val sizeBytes = (sizeValue * unitMultiplier.toDouble()).toLong()
                if (sizeBytes <= 0L) {
                    binding.tvStatus.text = getString(R.string.status_invalid_size)
                    return@setPositiveButton
                }
                val fsType = when (fsSpinner.selectedItemPosition) {
                    0 -> 1
                    1 -> 2
                    2 -> 3
                    else -> {
                        binding.tvStatus.text = getString(R.string.status_invalid_fs)
                        return@setPositiveButton
                    }
                }
                createNewContainer(uri, password, sizeBytes, fsType)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun createNewContainer(uri: Uri, password: ByteArray, sizeBytes: Long, fsType: Int) {
        binding.tvStatus.text = getString(R.string.status_opening)
        Thread {
            val result = try {
                contentResolver.openFileDescriptor(uri, "rw")?.use { pfd ->
                    val entropy = ByteArray(64).also {
                        java.security.SecureRandom().nextBytes(it)
                    }
                    NativeBridge.nativeCreateContainer(
                        pfd.fd,
                        password,
                        entropy,
                        sizeBytes,
                        fsType
                    )
                } ?: -1
            } catch (e: Exception) {
                Log.e(TAG, "Container creation failed", e)
                -1
            }

            runOnUiThread {
                binding.tvStatus.text = if (result == 0) {
                    if (fsType == 3) getString(R.string.status_ntfs_limited)
                    else getString(R.string.status_create_success)
                } else {
                    getString(R.string.status_create_failed)
                }
            }
        }.start()
    }

    private fun showRootMountDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.root_mount_hint)
            setText("/mnt/veracrypt/main")
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.root_mount_title)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val pfd = containerPfd ?: run {
                    binding.tvStatus.text = getString(R.string.status_error_open)
                    return@setPositiveButton
                }
                Thread {
                    val mountPoint = input.text.toString()
                    val result = NativeBridge.nativePrepareFuseMount(
                        pfd.fd,
                        mountPoint,
                        true
                    )
                    val rootReady = if (result == 0) RootFuseManager.prepareMountPoint(mountPoint) else false
                    runOnUiThread {
                        binding.tvStatus.text = if (result == 0 && rootReady) {
                            getString(R.string.status_mount_ready)
                        } else {
                            getString(R.string.status_write_failed)
                        }
                    }
                }.start()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
