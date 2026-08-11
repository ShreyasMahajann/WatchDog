package com.watchdog.app.devicewatch.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface DeviceWatchDao {

    /** Devices in a scope, unknown-present first, then trusted-present, then offline. */
    @Query(
        "SELECT * FROM watched_devices WHERE scopeKey = :scopeKey " +
            "ORDER BY present DESC, trusted ASC, firstSeen DESC",
    )
    fun observeScope(scopeKey: String): Flow<List<WatchedDeviceEntity>>

    @Query("SELECT * FROM watched_devices WHERE scopeKey = :scopeKey")
    suspend fun devicesInScope(scopeKey: String): List<WatchedDeviceEntity>

    @Query("SELECT * FROM watched_devices WHERE id = :id")
    fun observeById(id: Long): Flow<WatchedDeviceEntity?>

    /** New rows only; IGNORE guards against a stray (scopeKey, ip) collision. */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(rows: List<WatchedDeviceEntity>)

    @Update
    suspend fun updateAll(rows: List<WatchedDeviceEntity>)

    /** Flip every device in the scope that wasn't just seen to offline. */
    @Query("UPDATE watched_devices SET present = 0 WHERE scopeKey = :scopeKey AND ip NOT IN (:seenIps)")
    suspend fun markAbsent(scopeKey: String, seenIps: Collection<String>)

    @Query("UPDATE watched_devices SET present = 0 WHERE scopeKey = :scopeKey")
    suspend fun markAllAbsent(scopeKey: String)

    @Query("UPDATE watched_devices SET trusted = :trusted WHERE id = :id")
    suspend fun setTrusted(id: Long, trusted: Boolean)

    @Query("UPDATE watched_devices SET label = :label WHERE id = :id")
    suspend fun setLabel(id: Long, label: String?)

    @Query("DELETE FROM watched_devices WHERE id = :id")
    suspend fun deleteById(id: Long)
}
