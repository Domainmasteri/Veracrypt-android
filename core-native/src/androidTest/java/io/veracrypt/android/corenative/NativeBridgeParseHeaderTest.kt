package io.veracrypt.android.corenative

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented test that validates [NativeBridge.nativeOpen] against a known-good
 * VeraCrypt container bundled in androidTest/assets/test.vc.
 *
 * Container details:
 *   Algorithm : AES-256-XTS
 *   PRF       : PBKDF2-HMAC-SHA512, 500 000 iterations
 *   Password  : "test"
 *   Salt      : fixed 64-byte value (see generate_test_container.py)
 *   SHA-256   : b030a4c46cdad4393bc6f946c594c715441c27303c2b3220374ca33648d735f1
 */
@RunWith(AndroidJUnit4::class)
class NativeBridgeParseHeaderTest {

    @Test
    fun cryptoKnownAnswerSelfTests_pass() {
        assertTrue(NativeBridge.nativeRunCryptoSelfTests())
        assertTrue(NativeBridge.nativeRunFilesystemSelfTests())
    }

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
    fun nativeOpen_returnsSession_forKnownContainer() {
        val pfd      = assetToPfd("test.vc")
        val password = "test".toByteArray(Charsets.UTF_8)
        val session = NativeBridge.nativeOpen(pfd.fd, password)
        password.fill(0)
        pfd.close()

        assertTrue("nativeOpen should return a positive handle, got $session", session > 0L)
        assertTrue(NativeBridge.nativeIsOpen(session))
        NativeBridge.nativeClose(session)
        assertFalse(NativeBridge.nativeIsOpen(session))
    }

    @Test
    fun nativeOpen_returnsWrongPassword_forBadPassword() {
        val pfd      = assetToPfd("test.vc")
        val password = "wrong_password".toByteArray(Charsets.UTF_8)
        val result = NativeBridge.nativeOpen(pfd.fd, password)
        password.fill(0)
        pfd.close()

        assertEquals(
            "nativeOpen should return -1 for an incorrect passphrase",
            NativeBridge.OPEN_WRONG_PASSWORD, result
        )
    }

    @Test
    fun twoSessions_areIndependent_andCloseIsIdempotent() {
        val firstPfd = assetToPfd("test.vc")
        val secondPfd = assetToPfd("test.vc")
        val firstPassword = "test".toByteArray()
        val secondPassword = "test".toByteArray()

        val first = NativeBridge.nativeOpen(firstPfd.fd, firstPassword)
        val second = NativeBridge.nativeOpen(secondPfd.fd, secondPassword)
        firstPassword.fill(0)
        secondPassword.fill(0)
        firstPfd.close()
        secondPfd.close()

        assertTrue(first > 0L)
        assertTrue(second > 0L)
        assertNotEquals(first, second)
        NativeBridge.nativeClose(first)
        NativeBridge.nativeClose(first)
        assertFalse(NativeBridge.nativeIsOpen(first))
        assertTrue(NativeBridge.nativeIsOpen(second))
        NativeBridge.nativeClose(second)
    }

    @Test
    fun fat32_nestedUnicodeName_andCrossClusterRead_work() {
        val pfd = assetToPfd("fat32_test.vc")
        val password = "test".toByteArray()
        val session = NativeBridge.nativeOpen(pfd.fd, password)
        password.fill(0)
        pfd.close()
        assertTrue(session > 0L)

        assertEquals(NativeBridge.FS_FAT32, NativeBridge.nativeGetFileSystemType(session))
        val root = requireNotNull(NativeBridge.nativeListDir(session, "/"))
        assertEquals(1, root.size)
        assertEquals("/NESTED", root.single().path)
        assertTrue(root.single().isDirectory)

        val nested = requireNotNull(NativeBridge.nativeListDir(session, "/NESTED"))
        val file = nested.single()
        assertEquals("hello-long-😀.txt", file.name)
        assertEquals(192L * 1024L, file.sizeBytes)
        val actual = requireNotNull(NativeBridge.nativeReadFile(session, file.path, 480, 120))
        val expected = ByteArray(120) { index -> ((index + 480) * 17 + 3).toByte() }
        assertArrayEquals(expected, actual)
        NativeBridge.nativeClose(session)
    }

    @Test
    fun exfat_nestedFragmentedFatChain_andCrossClusterRead_work() {
        val pfd = assetToPfd("exfat_test.vc")
        val password = "test".toByteArray()
        val session = NativeBridge.nativeOpen(pfd.fd, password)
        password.fill(0)
        pfd.close()
        assertTrue(session > 0L)

        assertEquals(NativeBridge.FS_EXFAT, NativeBridge.nativeGetFileSystemType(session))
        val root = requireNotNull(NativeBridge.nativeListDir(session, "/"))
        assertEquals("/NESTED", root.single().path)
        val nested = requireNotNull(NativeBridge.nativeListDir(session, "/NESTED"))
        val file = nested.single()
        assertEquals("fragmented.bin", file.name)
        assertEquals(700L, file.sizeBytes)
        val actual = requireNotNull(NativeBridge.nativeReadFile(session, file.path, 490, 100))
        val expected = ByteArray(100) { index -> ((index + 490) * 29 + 11).toByte() }
        assertArrayEquals(expected, actual)
        NativeBridge.nativeClose(session)
    }
}
