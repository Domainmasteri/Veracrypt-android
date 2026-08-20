package io.veracrypt.android

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.WindowManager
import android.widget.EditText
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import io.veracrypt.android.corenative.ContainerSessionManager
import io.veracrypt.android.corenative.SessionOpenResult
import io.veracrypt.android.databinding.ActivityMainBinding
import io.veracrypt.android.providersaf.VeraCryptDocumentsProvider
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

private const val TAG = "MainActivity"

/**
 * Main entry point of the VeraCrypt Android read-only MVP.
 *
 * Allows the user to pick a VeraCrypt container file via the Storage Access
 * Framework, prompts for the password, then passes the raw file descriptor and
 * password to the native bridge for header decryption.
 *
 * Native code duplicates the selected descriptor into an opaque session. The
 * picker descriptor is then closed and only the session is exposed to UI/SAF.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val pickContainer = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            onContainerSelected(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnOpenContainer.setOnClickListener {
            pickContainer.launch(arrayOf("*/*"))
        }
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
                val password = encodePassword(input.text)
                input.text.clear()
                openContainerWithPassword(uri, password)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
            .also { dialog -> dialog.setOnDismissListener { input.text.clear() } }
    }

    private fun openContainerWithPassword(uri: Uri, password: ByteArray) {
        binding.tvStatus.text = getString(R.string.status_opening)
        binding.btnOpenContainer.isEnabled = false

        Thread {
            val openResult = try {
                // The current product boundary is strictly read-only. Requesting a
                // writable descriptor would unnecessarily widen the damage surface.
                contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    ContainerSessionManager.open(pfd.fd, password)
                } ?: SessionOpenResult.IoError
            } catch (e: Exception) {
                Log.e(TAG, "Container open failed")
                SessionOpenResult.IoError
            } finally {
                password.fill(0)
            }

            runOnUiThread {
                binding.btnOpenContainer.isEnabled = true

                when (openResult) {
                    is SessionOpenResult.Success -> {
                        VeraCryptDocumentsProvider.mount(openResult.session)
                        binding.tvStatus.text = getString(R.string.status_mounted)
                        startActivity(Intent(this, FileExplorerActivity::class.java))
                    }
                    SessionOpenResult.WrongPassword ->
                        binding.tvStatus.text = getString(R.string.status_wrong_password)
                    SessionOpenResult.CorruptHeader ->
                        binding.tvStatus.text = getString(R.string.status_corrupt_header)
                    SessionOpenResult.UnsupportedHeader ->
                        binding.tvStatus.text = getString(R.string.status_unsupported_header)
                    SessionOpenResult.UnsupportedFileSystem ->
                        binding.tvStatus.text = getString(R.string.status_unsupported_filesystem)
                    SessionOpenResult.InvalidFormat ->
                        binding.tvStatus.text = getString(R.string.status_error_format)
                    SessionOpenResult.IoError ->
                        binding.tvStatus.text = getString(R.string.status_error_io)
                }
            }
        }.start()
    }

    private fun encodePassword(characters: CharSequence): ByteArray {
        val encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(characters))
        val result = ByteArray(encoded.remaining())
        encoded.get(result)
        if (encoded.hasArray()) encoded.array().fill(0)
        return result
    }

}
