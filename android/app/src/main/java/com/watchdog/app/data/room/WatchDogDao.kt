package com.watchdog.app.data.room

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface WatchDogDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertNetwork(network: NetworkEntity)

    @Insert
    suspend fun insertScan(scan: ScanEntity): Long

    @Query("UPDATE scans SET status = :status, finishedAt = :finishedAt WHERE id = :scanId")
    suspend fun setScanStatus(scanId: Long, status: String, finishedAt: Long?)

    @Query("SELECT * FROM scans WHERE id = :scanId")
    fun observeScan(scanId: Long): Flow<ScanEntity?>

    @Query("SELECT * FROM scans ORDER BY startedAt DESC LIMIT :limit")
    fun observeRecentScans(limit: Int = 25): Flow<List<ScanEntity>>

    @Insert
    suspend fun insertHost(host: HostEntity): Long

    @Query("SELECT * FROM hosts WHERE scanId = :scanId ORDER BY id")
    fun observeHosts(scanId: Long): Flow<List<HostEntity>>

    @Insert
    suspend fun insertPort(port: PortEntity): Long

    @Insert
    suspend fun insertService(service: ServiceEntity): Long

    @Insert
    suspend fun insertFingerprint(fp: FingerprintEntity): Long

    @Query(
        """
        SELECT s.* FROM services s
        INNER JOIN ports p ON s.portId = p.id
        INNER JOIN hosts h ON p.hostId = h.id
        WHERE h.scanId = :scanId
        ORDER BY h.ip, p.port
        """,
    )
    fun observeServices(scanId: Long): Flow<List<ServiceEntity>>

    @Insert
    suspend fun insertFindings(findings: List<FindingEntity>)

    @Query("SELECT * FROM findings WHERE scanId = :scanId ORDER BY suppressed ASC, priority DESC")
    fun observeFindings(scanId: Long): Flow<List<FindingEntity>>
}
