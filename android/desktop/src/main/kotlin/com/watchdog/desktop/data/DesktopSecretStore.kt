package com.watchdog.desktop.data

import com.watchdog.app.wpa.creds.SecretStore
import java.io.File

/**
 * Desktop [SecretStore] for the WPA-sec key. Stored in a local file under the app
 * data dir with owner-only permissions where the OS supports it. Unlike Android's
 * Keystore-wrapped store this is not encrypted at rest — acceptable for a
 * single-user personal machine; documented as such.
 */
class DesktopSecretStore(
    private val file: File = File(AppDirs.dataDir(), "wpa_sec.key"),
) : SecretStore {

    override fun getKey(): String? =
        runCatching { if (file.exists()) file.readText().trim().ifBlank { null } else null }.getOrNull()

    fun setKey(key: String) {
        runCatching {
            file.parentFile?.mkdirs()
            file.writeText(key.trim())
            runCatching { file.setReadable(false, false); file.setReadable(true, true); file.setWritable(false, false); file.setWritable(true, true) }
        }
    }

    fun clear() { runCatching { file.delete() } }

    fun isConfigured(): Boolean = getKey() != null

    companion object {
        /** WPA-sec keys are 32 lowercase hex chars. Advisory only. */
        fun looksValid(key: String): Boolean = key.trim().matches(Regex("[0-9a-fA-F]{32}"))
    }
}
