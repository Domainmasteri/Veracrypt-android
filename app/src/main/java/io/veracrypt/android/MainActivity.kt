package io.veracrypt.android

import android.net.Uri
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import io.veracrypt.android.databinding.ActivityMainBinding

/**
 * Main entry point of the VeraCrypt Android read-only MVP.
 *
 * Allows the user to pick a VeraCrypt container file via the Storage Access
 * Framework and hands it off to the native bridge for header parsing.
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
        // TODO: pass URI to NativeBridge for VeraCrypt header parsing
    }
}
