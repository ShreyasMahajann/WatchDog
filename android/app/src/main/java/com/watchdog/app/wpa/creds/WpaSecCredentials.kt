package com.watchdog.app.wpa.creds

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Open [opener], and if it throws (a corrupt/undecryptable store), run [wiper] once
 * and retry. If the retry also throws, return null instead of propagating — the
 * caller degrades gracefully rather than crashing. [wiper] failures are swallowed.
 */
internal fun <T> openWithRecovery(opener: () -> T, wiper: () -> Unit): T? =
    try {
        opener()
    } catch (first: Exception) {
        runCatching { wiper() }
        try {
            opener()
        } catch (second: Exception) {
            null
        }
    }

/**
 * Securely stores the WPA-sec submission key. Backed by [EncryptedSharedPreferences] (AES-256,
 * key wrapped by the Android Keystore), so the token is encrypted at rest and never lives in
 * source, DataStore, or logs. The key is only ever read to build the request cookie.
 *
 * The encrypted store can become undecryptable if the Keystore master key and the on-disk
 * keyset fall out of sync (e.g. after a backup/restore or reinstall over existing data),
 * which throws [javax.crypto.AEADBadTagException] on open. Because this class is touched at
 * app startup, that once crashed the whole app — so opening now recovers by wiping the
 * corrupt store and starting fresh, and every access degrades to null rather than throwing.
 */
class WpaSecCredentials(context: Context) {

    private val appContext = context.applicationContext

    private val prefs: SharedPreferences? by lazy {
        openWithRecovery(
            opener = { createEncryptedPrefs() },
            wiper = { wipeCorruptStore() },
        )
    }

    private fun createEncryptedPrefs(): SharedPreferences {
        val master = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            appContext,
            PREFS_NAME,
            master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    /** Delete the backing prefs file and evict Android's in-process cache. */
    private fun wipeCorruptStore() {
        Log.w("WpaSecCredentials", "Encrypted prefs unreadable; wiping and recreating")
        appContext.deleteSharedPreferences(PREFS_NAME)
    }

    fun getKey(): String? = runCatching { prefs?.getString(KEY, null) }.getOrNull()?.takeIf { it.isNotBlank() }

    fun setKey(key: String) {
        runCatching { prefs?.edit()?.putString(KEY, key.trim())?.apply() }
    }

    fun clear() {
        runCatching { prefs?.edit()?.remove(KEY)?.apply() }
    }

    fun isConfigured(): Boolean = getKey() != null

    companion object {
        private const val PREFS_NAME = "wpa_sec_secure"
        private const val KEY = "submission_key"

        /** WPA-sec keys are 32 lowercase hex chars. Advisory only — used to warn, not to block. */
        fun looksValid(key: String): Boolean = key.trim().matches(Regex("[0-9a-fA-F]{32}"))
    }
}
