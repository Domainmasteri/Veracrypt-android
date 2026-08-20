package io.veracrypt.android

import android.os.ParcelFileDescriptor
import android.os.CancellationSignal
import android.os.SystemClock
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.widget.ListView
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import io.veracrypt.android.corenative.ContainerSessionManager
import io.veracrypt.android.corenative.SessionOpenResult
import io.veracrypt.android.providersaf.VeraCryptDocumentsProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileNotFoundException

@RunWith(AndroidJUnit4::class)
class ReadOnlyProviderInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun unmount() {
        VeraCryptDocumentsProvider.unmount()
    }

    @Test
    fun providerResolvesNestedDocumentsAndRejectsUnknownOrDirectoryOpen() {
        mountAsset("fat32_test.vc")
        val resolver = context.contentResolver
        val rootChildren = DocumentsContract.buildChildDocumentsUri(
            "io.veracrypt.android.documents", "/"
        )
        resolver.query(rootChildren, null, null, null, null).use { cursor ->
            assertNotNull(cursor)
            assertEquals(1, cursor!!.count)
        }

        val nestedChildren = DocumentsContract.buildChildDocumentsUri(
            "io.veracrypt.android.documents", "/NESTED"
        )
        resolver.query(nestedChildren, null, null, null, null).use { cursor ->
            assertNotNull(cursor)
            assertEquals(1, cursor!!.count)
        }

        val fileUri = DocumentsContract.buildDocumentUri(
            "io.veracrypt.android.documents", "/NESTED/hello-long-😀.txt"
        )
        resolver.openInputStream(fileUri).use { input ->
            assertNotNull(input)
            assertEquals(192 * 1024, input!!.readBytes().size)
        }

        val directoryUri = DocumentsContract.buildDocumentUri(
            "io.veracrypt.android.documents", "/NESTED"
        )
        expectFileNotFound { resolver.openFileDescriptor(directoryUri, "r")?.close() }
        val unknownUri = DocumentsContract.buildDocumentUri(
            "io.veracrypt.android.documents", "/missing.txt"
        )
        expectFileNotFound { resolver.query(unknownUri, null, null, null, null)?.close() }
    }

    @Test
    fun externalViewerClientGetsMetadataAndReadOnlyPlaintext() {
        mountAsset("fat32_test.vc")
        val uri = ContainerViewerProvider.buildUri("/NESTED/hello-long-😀.txt")
        context.contentResolver.query(uri, null, null, null, null).use { cursor ->
            assertNotNull(cursor)
            assertTrue(cursor!!.moveToFirst())
            assertEquals("hello-long-😀.txt",
                cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)))
            assertEquals(192L * 1024L,
                cursor.getLong(cursor.getColumnIndexOrThrow(OpenableColumns.SIZE)))
        }
        context.contentResolver.openInputStream(uri).use { input ->
            assertNotNull(input)
            val prefix = ByteArray(1024)
            assertEquals(prefix.size, input!!.read(prefix))
            assertEquals(ByteArray(prefix.size) { index -> (index * 17 + 3).toByte() }.toList(),
                prefix.toList())
        }
        try {
            context.contentResolver.openFileDescriptor(uri, "w")?.close()
            fail("Viewer provider accepted write mode")
        } catch (_: UnsupportedOperationException) {
            // Expected read-only behavior.
        }
    }

    @Test
    fun cancellationAndUnmountTerminateActiveStreamAndExpireProviderState() {
        mountAsset("fat32_test.vc")
        val resolver = context.contentResolver
        val uri = DocumentsContract.buildDocumentUri(
            "io.veracrypt.android.documents", "/NESTED/hello-long-😀.txt"
        )
        val cancellation = CancellationSignal()
        val descriptor = requireNotNull(resolver.openFileDescriptor(uri, "r", cancellation))
        cancellation.cancel()
        VeraCryptDocumentsProvider.unmount()
        assertFalse(VeraCryptDocumentsProvider.isMounted())

        val readResult = runCatching {
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
        }
        assertTrue(
            "Cancelled stream unexpectedly returned the complete plaintext",
            readResult.isFailure || readResult.getOrThrow().size < 192 * 1024
        )

        val rootsUri = DocumentsContract.buildRootsUri("io.veracrypt.android.documents")
        resolver.query(rootsUri, null, null, null, null).use { cursor ->
            assertNotNull(cursor)
            assertEquals(0, cursor!!.count)
        }
        expectFileNotFound { resolver.query(uri, null, null, null, null)?.close() }
    }

    @Test
    fun explorerRestoresNestedPathAfterActivityRecreation() {
        mountAsset("fat32_test.vc")
        ActivityScenario.launch(FileExplorerActivity::class.java).use { scenario ->
            waitForActivity(scenario) { activity ->
                val list = activity.findViewById<ListView>(R.id.list_entries)
                list.adapter?.count == 1 && list.childCount > 0
            }
            scenario.onActivity { activity ->
                val list = activity.findViewById<ListView>(R.id.list_entries)
                list.performItemClick(list.getChildAt(0), 0, list.adapter.getItemId(0))
            }
            waitForActivity(scenario) { activity ->
                activity.findViewById<TextView>(R.id.tv_current_path).text.toString() == "/NESTED"
            }
            scenario.recreate()
            waitForActivity(scenario) { activity ->
                activity.findViewById<TextView>(R.id.tv_current_path).text.toString() == "/NESTED" &&
                    activity.findViewById<ListView>(R.id.list_entries).adapter?.count == 1
            }
        }
    }

    private fun mountAsset(name: String) {
        val temp = File(context.cacheDir, name)
        context.assets.open(name).use { source ->
            temp.outputStream().use { destination -> source.copyTo(destination) }
        }
        ParcelFileDescriptor.open(temp, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            val password = "test".toByteArray()
            val result = ContainerSessionManager.open(pfd.fd, password)
            password.fill(0)
            if (result !is SessionOpenResult.Success) fail("Could not mount test fixture: $result")
            VeraCryptDocumentsProvider.mount((result as SessionOpenResult.Success).session)
        }
    }

    private fun expectFileNotFound(block: () -> Unit) {
        try {
            block()
            fail("Expected FileNotFoundException")
        } catch (_: FileNotFoundException) {
            // Expected fail-closed provider behavior.
        }
    }

    private fun waitForActivity(
        scenario: ActivityScenario<FileExplorerActivity>,
        condition: (FileExplorerActivity) -> Boolean
    ) {
        repeat(100) {
            var satisfied = false
            scenario.onActivity { activity -> satisfied = condition(activity) }
            if (satisfied) return
            SystemClock.sleep(25L)
        }
        fail("Timed out waiting for activity state")
    }
}
