package com.watchdog.desktop.data

import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Desktop [SettingsStore] backed by a JSON file under the app data dir. Same
 * fields and defaults as the Android DataStore-backed store.
 */
class DesktopSettingsStore(
    private val file: File = defaultFile(),
) : SettingsStore {

    @Serializable
    private data class Dto(
        val correlatorMode: String = CorrelatorMode.DIRECT_OSV.name,
        val serverBaseUrl: String = "",
        val serverToken: String = "",
        val defaultDepth: String = ScanDepth.TOP_1000.name,
    )

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }
    private val _settings = MutableStateFlow(load())
    override val settings: Flow<Settings> = _settings.asStateFlow()

    override suspend fun setMode(mode: CorrelatorMode) = update { it.copy(correlatorMode = mode) }
    override suspend fun setServer(url: String, token: String) =
        update { it.copy(serverBaseUrl = url.trim(), serverToken = token.trim()) }
    override suspend fun setDepth(depth: ScanDepth) = update { it.copy(defaultDepth = depth) }

    /** Snapshot for non-suspending callers (desktop UI). */
    fun current(): Settings = _settings.value

    private inline fun update(block: (Settings) -> Settings) {
        val next = block(_settings.value)
        _settings.value = next
        save(next)
    }

    private fun load(): Settings = try {
        if (!file.exists()) Settings()
        else json.decodeFromString(Dto.serializer(), file.readText()).toSettings()
    } catch (e: Exception) {
        Settings()
    }

    private fun save(s: Settings) {
        try {
            file.parentFile?.mkdirs()
            file.writeText(json.encodeToString(Dto.serializer(), s.toDto()))
        } catch (e: Exception) {
            // Non-fatal: settings just won't persist this session.
        }
    }

    private fun Dto.toSettings() = Settings(
        correlatorMode = runCatching { CorrelatorMode.valueOf(correlatorMode) }.getOrDefault(CorrelatorMode.DIRECT_OSV),
        serverBaseUrl = serverBaseUrl,
        serverToken = serverToken,
        defaultDepth = runCatching { ScanDepth.valueOf(defaultDepth) }.getOrDefault(ScanDepth.TOP_1000),
    )

    private fun Settings.toDto() = Dto(correlatorMode.name, serverBaseUrl, serverToken, defaultDepth.name)

    companion object {
        fun defaultFile(): File = File(AppDirs.dataDir(), "settings.json")
    }
}
