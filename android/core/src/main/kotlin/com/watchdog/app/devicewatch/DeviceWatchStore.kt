package com.watchdog.app.devicewatch

/**
 * Persistence the shared [DeviceWatchScanner] needs. Android backs it with Room,
 * desktop with sqlite. UI-facing queries (observe a scope, rename, trust, forget)
 * live on the platform stores; this interface is only the scanner's write path.
 */
interface DeviceWatchStore {
    /** Current baseline for a network scope. */
    suspend fun devicesInScope(scopeKey: String): List<WatchedDevice>

    /**
     * Commit a scan diff: insert new devices, refresh seen-again ones, then flip any
     * device in the scope not in [seenIps] to offline. Inserts/updates run before the
     * absence flip so the just-seen IPs are excluded from it.
     */
    suspend fun applyScan(
        toInsert: List<WatchedDevice>,
        toUpdate: List<WatchedDevice>,
        scopeKey: String,
        seenIps: Collection<String>,
    )
}
