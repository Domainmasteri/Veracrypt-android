package io.veracrypt.android

import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.text.InputType
import android.widget.EditText
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import io.veracrypt.android.corenative.NativeBridge
import io.veracrypt.android.databinding.ActivityMainBinding

/**
 * Main entry point of the VeraCrypt Android read-only MVP.
 *
 * Allows the user to pick a VeraCrypt container file via the Storage Access
 * Framework, prompts for the password, then passes the raw file descriptor and
 * password to the native bridge for header decryption.
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
            val result: Int
            try {
                pfd = contentResolver.openFileDescriptor(uri, "r")
                result = if (pfd != null) {
                    NativeBridge.nativeParseHeader(pfd.fd, password)
                } else {
                    Int.MIN_VALUE
                }
            } finally {
                pfd?.close()
            }

            runOnUiThread {
                binding.btnOpenContainer.isEnabled = true
                binding.tvStatus.text = when (result) {
                    0          -> getString(R.string.status_header_ok)
                    -1         -> getString(R.string.status_wrong_password)
                    Int.MIN_VALUE -> getString(R.string.status_error_open)
                    else       -> getString(R.string.status_error_format)
                }
            }
        }.start()
    }
}

