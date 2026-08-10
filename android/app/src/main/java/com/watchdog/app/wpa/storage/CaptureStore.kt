package com.watchdog.app.wpa.storage

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.watchdog.app.wpa.handshake.HandshakeAnalysis
import com.watchdog.app.wpa.handshake.HandshakeAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Owns capture files on disk (private app storage) and turns raw bytes into validated metadata.
 * Files are named by their MD5 so the same capture imported twice lands on the same path — the
 * identity used to avoid re-uploading and to link a local capture to its WPA-sec result.
 */
class CaptureStore(context: Context) {

    private val appContext = context.applicationContext
    val dir: File = File(appContext.filesDir, "wpa_captures").apply { mkdirs() }

    /** A capture that has been copied in and analyzed, ready to be persisted by the repository. */
    data class Imported(
        val filePath: String,
        val fileName: String,
        val sizeBytes: Long,
        val md5: String,
        val analysis: HandshakeAnalysis,
    )

    /** Copy the user-selected file in, validate it, and return its metadata. Throws if unreadable/not a pcap. */
    suspend fun importFromUri(uri: Uri): Imported = withContext(Dispatchers.IO) {
        val bytes = appContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IOException("Could not open the selected file.")
        importBytes(bytes, displayName(uri))
    }

    /** Validate bytes (via [HandshakeAnalyzer], which throws on non-pcap) and store them under their MD5. */
    fun importBytes(bytes: ByteArray, originalName: String): Imported {
        val analysis = HandshakeAnalyzer.analyze(bytes) // throws NotAPcapException on garbage
        val md5 = md5(bytes)
        val ext = originalName.substringAfterLast('.', "").lowercase()
            .filter { it.isLetterOrDigit() }.take(8).ifBlank { "pcap" }
        val file = File(dir, "$md5.$ext")
        if (!file.exists()) file.writeBytes(bytes)
        return Imported(file.absolutePath, originalName, bytes.size.toLong(), md5, analysis)
    }

    /** Re-read and re-analyze an already-stored capture (e.g. to recompute after a schema change). */
    suspend fun analyzeStored(path: String): HandshakeAnalysis = withContext(Dispatchers.IO) {
        HandshakeAnalyzer.analyze(File(path).readBytes())
    }

    fun delete(path: String) {
        runCatching { File(path).takeIf { it.parentFile == dir }?.delete() }
    }

    private fun displayName(uri: Uri): String {
        val fromResolver = runCatching {
            appContext.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        }.getOrNull()
        return fromResolver ?: uri.lastPathSegment?.substringAfterLast('/') ?: "capture.pcap"
    }

    private fun md5(bytes: ByteArray): String =
        MessageDigest.getInstance("MD5").digest(bytes).joinToString("") { "%02x".format(it) }
}
