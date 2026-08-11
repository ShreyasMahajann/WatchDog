package com.watchdog.app.devicewatch.data

import kotlinx.coroutines.flow.Flow

/** Persistence for watched devices. Thin wrapper over the DAO — the diff logic lives in
 *  DeviceWatchDiff so it stays pure and unit-testable. */
class DeviceWatchRepository(private val dao: DeviceWatchDao) {

    fun observeScope(scopeKey: String): Flow<List<WatchedDeviceEntity>> = dao.observeScope(scopeKey)
    fun observeById(id: Long): Flow<WatchedDeviceEntity?> = dao.observeById(id)
    suspend fun devicesInScope(scopeKey: String): List<WatchedDeviceEntity> = dao.devicesInScope(scopeKey)

    /**
     * Commit a scan's diff: insert newly-seen devices, refresh the ones seen again, then flip any
     * device in the scope that wasn't seen this round to offline. Order matters — absence is computed
     * from [seenIps], so inserts/updates run first and the just-seen IPs are excluded from the flip.
     */
    suspend fun applyScan(
        toInsert: List<WatchedDeviceEntity>,
        toUpdate: List<WatchedDeviceEntity>,
        scopeKey: String,
        seenIps: Collection<String>,
    ) {
        if (toInsert.isNotEmpty()) dao.insertAll(toInsert)
        if (toUpdate.isNotEmpty()) dao.updateAll(toUpdate)
        if (seenIps.isEmpty()) dao.markAllAbsent(scopeKey) else dao.markAbsent(scopeKey, seenIps)
    }

    suspend fun setTrusted(id: Long, trusted: Boolean) = dao.setTrusted(id, trusted)
    suspend fun rename(id: Long, label: String?) = dao.setLabel(id, label?.trim()?.ifBlank { null })
    suspend fun forget(id: Long) = dao.deleteById(id)
}
