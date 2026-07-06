package com.watchdog.app.correlate

import android.content.Context
import com.watchdog.app.correlate.direct.DirectOsvCorrelator
import com.watchdog.app.correlate.remote.RemoteCorrelator
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsRepository
import kotlinx.coroutines.flow.first

/** Which vulnerability source an on-demand check runs against. */
enum class CorrelationTarget { OSV, OWN_SERVER }

/**
 * Builds a [Correlator] on demand. Mirrors the correlator choice that used to be
 * private inside ScanController, now that correlation runs per device on request
 * rather than inline during the scan.
 */
class CorrelatorFactory(context: Context) {
    private val settingsRepo = SettingsRepository(context.applicationContext)

    /** OSV is always available; own-server only when a base URL is configured. */
    suspend fun availableTargets(): List<CorrelationTarget> = targetsFor(settingsRepo.settings.first())

    suspend fun create(target: CorrelationTarget): Correlator {
        val s = settingsRepo.settings.first()
        return when (target) {
            CorrelationTarget.OWN_SERVER ->
                if (s.serverBaseUrl.isNotBlank()) {
                    RemoteCorrelator(baseUrl = s.serverBaseUrl, token = s.serverToken.ifBlank { null })
                } else {
                    DirectOsvCorrelator() // misconfigured -> fall back
                }
            CorrelationTarget.OSV -> DirectOsvCorrelator()
        }
    }

    companion object {
        fun targetsFor(s: Settings): List<CorrelationTarget> =
            if (s.serverBaseUrl.isNotBlank()) {
                listOf(CorrelationTarget.OSV, CorrelationTarget.OWN_SERVER)
            } else {
                listOf(CorrelationTarget.OSV)
            }
    }
}
