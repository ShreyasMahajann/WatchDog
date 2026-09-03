package com.watchdog.app.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.watchdog.app.scan.ScanDepth
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

// Settings + CorrelatorMode + SettingsStore now live in :core (shared with desktop).

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "watchdog_settings")

/** Persists user preferences: which correlator, the own-server URL/token, depth. */
class SettingsRepository(private val context: Context) : SettingsStore {

    private object Keys {
        val MODE = stringPreferencesKey("correlator_mode")
        val URL = stringPreferencesKey("server_base_url")
        val TOKEN = stringPreferencesKey("server_token")
        val DEPTH = stringPreferencesKey("default_depth")
    }

    override val settings: Flow<Settings> = context.dataStore.data.map { prefs ->
        Settings(
            correlatorMode = prefs[Keys.MODE]?.let { runCatching { CorrelatorMode.valueOf(it) }.getOrNull() }
                ?: CorrelatorMode.DIRECT_OSV,
            serverBaseUrl = prefs[Keys.URL] ?: "",
            serverToken = prefs[Keys.TOKEN] ?: "",
            defaultDepth = prefs[Keys.DEPTH]?.let { runCatching { ScanDepth.valueOf(it) }.getOrNull() }
                ?: ScanDepth.TOP_1000,
        )
    }

    override suspend fun setMode(mode: CorrelatorMode) {
        context.dataStore.edit { it[Keys.MODE] = mode.name }
    }

    override suspend fun setServer(url: String, token: String) {
        context.dataStore.edit {
            it[Keys.URL] = url.trim()
            it[Keys.TOKEN] = token.trim()
        }
    }

    override suspend fun setDepth(depth: ScanDepth) {
        context.dataStore.edit { it[Keys.DEPTH] = depth.name }
    }
}
