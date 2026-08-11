package com.watchdog.app.devicewatch

import com.watchdog.app.devicewatch.data.DeviceWatchRepository
import com.watchdog.app.net.NetworkContext
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.ScanScope
import kotlinx.coroutines.flow.toList

/** Result of a Device Watch pass. */
sealed interface WatchOutcome {
    /** Not on a scannable Wi-Fi LAN — nothing to watch. */
    data object NoNetwork : WatchOutcome
    data class Scanned(val present: Int, val newCount: Int, val offline: Int) : WatchOutcome
}

/**
 * Runs one on-demand Device Watch pass: discover the LAN, diff against the stored baseline for the
 * current network, persist the result. Deliberately bypasses ScanController/ScanForegroundService/
 * ScanStateHolder (those are NetScan's process-global singletons and would clobber its live state
 * and history) — it drives the reusable, self-terminating [ScanEngine.discoverHosts] directly.
 *
 * [now] is injected so the diff is deterministic under test.
 */
class DeviceWatchScanner(
    private val networkContext: NetworkContext,
    private val engine: ScanEngine,
    private val repo: DeviceWatchRepository,
    private val now: () -> Long = { System.currentTimeMillis() },
) {

    suspend fun scan(
        config: ScanConfig = ScanConfig(scope = ScanScope.WHOLE_NETWORK),
    ): WatchOutcome {
        val net = networkContext.current()
        val cidr = net?.cidr
        if (net == null || !net.isWifi || cidr == null) return WatchOutcome.NoNetwork
        val scopeKey = WatchScope.of(net) ?: return WatchOutcome.NoNetwork
        val label = WatchScope.label(net)

        val discovered = engine.discoverHosts(cidr, config).toList()
        val existing = repo.devicesInScope(scopeKey)
        val diff = DeviceWatchDiff.compute(existing, discovered, scopeKey, label, now())

        repo.applyScan(diff.toInsert, diff.toUpdate, scopeKey, discovered.map { it.ip }.toSet())

        return WatchOutcome.Scanned(
            present = diff.present,
            newCount = diff.newCount,
            offline = diff.offline,
        )
    }
}
