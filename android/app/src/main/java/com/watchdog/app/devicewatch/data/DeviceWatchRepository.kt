package com.watchdog.app.devicewatch.data

import com.watchdog.app.devicewatch.DeviceWatchStore
import com.watchdog.app.devicewatch.WatchedDevice
import kotlinx.coroutines.flow.Flow

/** Persistence for watched devices. Thin wrapper over the DAO — the diff logic lives in
 *  DeviceWatchDiff (in :core) so it stays pure and unit-testable. Implements the shared
 *  [DeviceWatchStore] (scanner write-path) by mapping Room entities to/from the pure model;
 *  the UI keeps observing the Room entity directly. */
class DeviceWatchRepository(private val dao: DeviceWatchDao) : DeviceWatchStore {

    fun observeScope(scopeKey: String): Flow<List<WatchedDeviceEntity>> = dao.observeScope(scopeKey)
    fun observeById(id: Long): Flow<WatchedDeviceEntity?> = dao.observeById(id)

    override suspend fun devicesInScope(scopeKey: String): List<WatchedDevice> =
        dao.devicesInScope(scopeKey).map { it.toModel() }

    /**
     * Commit a scan's diff: insert newly-seen devices, refresh the ones seen again, then flip any
     * device in the scope that wasn't seen this round to offline. Order matters — absence is computed
     * from [seenIps], so inserts/updates run first and the just-seen IPs are excluded from the flip.
     */
    override suspend fun applyScan(
        toInsert: List<WatchedDevice>,
        toUpdate: List<WatchedDevice>,
        scopeKey: String,
        seenIps: Collection<String>,
    ) {
        if (toInsert.isNotEmpty()) dao.insertAll(toInsert.map { it.toEntity() })
        if (toUpdate.isNotEmpty()) dao.updateAll(toUpdate.map { it.toEntity() })
        if (seenIps.isEmpty()) dao.markAllAbsent(scopeKey) else dao.markAbsent(scopeKey, seenIps)
    }

    suspend fun setTrusted(id: Long, trusted: Boolean) = dao.setTrusted(id, trusted)
    suspend fun rename(id: Long, label: String?) = dao.setLabel(id, label?.trim()?.ifBlank { null })
    suspend fun forget(id: Long) = dao.deleteById(id)
}

private fun WatchedDeviceEntity.toModel() = WatchedDevice(
    id = id, scopeKey = scopeKey, networkLabel = networkLabel, ip = ip, hostname = hostname,
    serviceHints = serviceHints, label = label, trusted = trusted,
    firstSeen = firstSeen, lastSeen = lastSeen, present = present,
)

private fun WatchedDevice.toEntity() = WatchedDeviceEntity(
    id = id, scopeKey = scopeKey, networkLabel = networkLabel, ip = ip, hostname = hostname,
    serviceHints = serviceHints, label = label, trusted = trusted,
    firstSeen = firstSeen, lastSeen = lastSeen, present = present,
)
