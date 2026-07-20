package io.veracrypt.android.corenative

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented test that validates [NativeBridge.nativeParseHeader] against a known-good
 * VeraCrypt container bundled in androidTest/assets/test.vc.
 *
 * Container details:
 *   Algorithm : AES-256-XTS
 *   PRF       : PBKDF2-HMAC-SHA512, 500 000 iterations
 *   Password  : "test"
 *   Salt      : fixed 64-byte value (see generate_test_container.py)
 *   SHA-256   : b71651db848746d13e2b64c2f6d628b34ab74ca7f723006ef380a5e02212687a
 */
@RunWith(AndroidJUnit4::class)
class NativeBridgeParseHeaderTest {

    /**
     * Copy the asset to a temporary file and return a read-only
     * [ParcelFileDescriptor] so we can extract a raw int fd.
     */
    private fun assetToPfd(assetName: String): ParcelFileDescriptor {
        val ctx  = InstrumentationRegistry.getInstrumentation().context
        val tmp  = File(ctx.cacheDir, assetName)
        ctx.assets.open(assetName).use { src -> tmp.outputStream().use { src.copyTo(it) } }
        return ParcelFileDescriptor.open(tmp, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    @Test
    fun nativeParseHeader_returnsSuccess_forKnownContainer() {
        val pfd      = assetToPfd("test.vc")
        val password = "test".toByteArray(Charsets.UTF_8)
        val result   = NativeBridge.nativeParseHeader(pfd.fd, password)
        pfd.close()

        assertEquals(
            "nativeParseHeader should return 0 (success) for the known container, got $result",
            0, result
        )
    }

    @Test
    fun nativeParseHeader_returnsWrongPassword_forBadPassword() {
        val pfd      = assetToPfd("test.vc")
        val password = "wrong_password".toByteArray(Charsets.UTF_8)
        val result   = NativeBridge.nativeParseHeader(pfd.fd, password)
        pfd.close()

        assertEquals(
            "nativeParseHeader should return -1 (wrong password) for incorrect passphrase",
            -1, result
        )
    }
}
