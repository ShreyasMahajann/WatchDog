package com.watchdog.app.wpa.creds

/**
 * Read access to the stored WPA-sec submission key. Android backs this with
 * EncryptedSharedPreferences; desktop with a local key file. Only the read the
 * submission service needs lives here; set/clear are platform UI concerns.
 */
interface SecretStore {
    fun getKey(): String?
}
