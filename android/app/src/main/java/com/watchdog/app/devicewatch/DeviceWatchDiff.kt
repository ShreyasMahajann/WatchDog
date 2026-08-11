package com.watchdog.app.devicewatch

import com.watchdog.app.devicewatch.data.WatchedDeviceEntity
import com.watchdog.app.scan.discovery.DiscoveredHost

/** The outcome of diffing a fresh discovery against the stored baseline. */
data class WatchDiff(
    /** Devices never seen before in this scope (id=0, untrusted). */
    val toInsert: List<WatchedDeviceEntity>,
    /** Devices already known, refreshed to present (carry their existing id + trust/label). */
    val toUpdate: List<WatchedDeviceEntity>,
    /** How many devices were seen this scan (insert + update). */
    val present: Int,
    /** How many of those are brand-new (== toInsert.size). */
    val newCount: Int,
    /** Known devices in this scope that were NOT seen this scan. */
    val offline: Int,
)

/**
 * Pure diff of a discovery pass against the stored baseline for one network scope. No I/O, no
 * android.* — the whole risk of the feature (what counts as "new", what stays "known", what goes
 * "offline") lives here so it can be unit-tested exhaustively.
 */
object DeviceWatchDiff {

    fun compute(
        existing: List<WatchedDeviceEntity>,
        discovered: List<DiscoveredHost>,
        scopeKey: String,
        networkLabel: String,
        now: Long,
    ): WatchDiff {
        val byIp = existing.associateBy { it.ip }
        val seen = LinkedHashSet<String>()
        val toInsert = ArrayList<WatchedDeviceEntity>()
        val toUpdate = ArrayList<WatchedDeviceEntity>()

        for (host in discovered) {
            if (!seen.add(host.ip)) continue // discovery already dedups by IP; guard anyway
            val prior = byIp[host.ip]
            if (prior == null) {
                toInsert += WatchedDeviceEntity(
                    scopeKey = scopeKey,
                    networkLabel = networkLabel,
                    ip = host.ip,
                    hostname = host.hostname,
                    serviceHints = host.serviceHints.joinToString(","),
                    label = null,
                    trusted = false,
                    firstSeen = now,
                    lastSeen = now,
                    present = true,
                )
            } else {
                toUpdate += prior.copy(
                    networkLabel = networkLabel,
                    // Keep the richer signal: don't overwrite a known hostname/hints with a blank.
                    hostname = host.hostname ?: prior.hostname,
                    serviceHints = if (host.serviceHints.isNotEmpty()) {
                        host.serviceHints.joinToString(",")
                    } else {
                        prior.serviceHints
                    },
                    lastSeen = now,
                    present = true,
                )
            }
        }

        val offline = existing.count { it.ip !in seen }
        return WatchDiff(
            toInsert = toInsert,
            toUpdate = toUpdate,
            present = seen.size,
            newCount = toInsert.size,
            offline = offline,
        )
    }
}
