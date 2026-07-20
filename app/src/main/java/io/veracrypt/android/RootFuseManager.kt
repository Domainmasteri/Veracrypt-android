package io.veracrypt.android

import android.util.Log

private const val ROOT_TAG = "RootFuseManager"

/**
 * Root helper for advanced FUSE mounting workflows.
 *
 * This component executes best-effort shell integration only when a rooted
 * environment is available (`su` binary present and functional).
 */
object RootFuseManager {

    fun prepareMountPoint(mountPoint: String): Boolean {
        return runRootCommand("mkdir -p \"$mountPoint\" && chmod 0775 \"$mountPoint\"")
    }

    fun mountWithFuse(
        encryptedFilePath: String,
        mountPoint: String,
        readWrite: Boolean
    ): Boolean {
        val mode = if (readWrite) "rw" else "ro"
        val command = "mount -o $mode,bind \"$encryptedFilePath\" \"$mountPoint\""
        return runRootCommand(command)
    }

    private fun runRootCommand(command: String): Boolean {
        return try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            val code = process.waitFor()
            if (code != 0) {
                Log.w(ROOT_TAG, "Root command failed ($code): $command")
            }
            code == 0
        } catch (e: Exception) {
            Log.w(ROOT_TAG, "Root command unavailable: $command", e)
            false
        }
    }
}
