package com.watchdog.app.wpa.creds

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Securely stores the WPA-sec submission key. Backed by [EncryptedSharedPreferences] (AES-256,
 * key wrapped by the Android Keystore), so the token is encrypted at rest and never lives in
 * source, DataStore, or logs. The key is only ever read to build the request cookie.
 */
class WpaSecCredentials(context: Context) {

    private val prefs by lazy {
        val master = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context.applicationContext,
            "wpa_sec_secure",
            master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun getKey(): String? = prefs.getString(KEY, null)?.takeIf { it.isNotBlank() }

    fun setKey(key: String) {
        prefs.edit().putString(KEY, key.trim()).apply()
    }

    fun clear() {
        prefs.edit().remove(KEY).apply()
    }

    fun isConfigured(): Boolean = getKey() != null

    companion object {
        private const val KEY = "submission_key"

        /** WPA-sec keys are 32 lowercase hex chars. Advisory only — used to warn, not to block. */
        fun looksValid(key: String): Boolean = key.trim().matches(Regex("[0-9a-fA-F]{32}"))
    }
}
