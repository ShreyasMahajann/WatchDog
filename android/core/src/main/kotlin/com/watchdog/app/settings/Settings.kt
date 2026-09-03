package com.watchdog.app.settings

import com.watchdog.app.scan.ScanDepth
import kotlinx.coroutines.flow.Flow

/** Where CVE correlation runs. */
enum class CorrelatorMode { DIRECT_OSV, OWN_SERVER }

/** User preferences, shared by the Android and desktop apps. */
data class Settings(
    val correlatorMode: CorrelatorMode = CorrelatorMode.DIRECT_OSV,
    val serverBaseUrl: String = "",
    val serverToken: String = "",
    val defaultDepth: ScanDepth = ScanDepth.TOP_1000,
)

/**
 * Persists [Settings]. Android backs this with DataStore; desktop with a JSON
 * file. Kept as an interface so shared/presentation code can depend on the
 * abstraction rather than a platform store.
 */
interface SettingsStore {
    val settings: Flow<Settings>
    suspend fun setMode(mode: CorrelatorMode)
    suspend fun setServer(url: String, token: String)
    suspend fun setDepth(depth: ScanDepth)
}
