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

    /** One row per fingerprinted service with its host IP + port, for on-demand correlation. */
    @Query(
        """
        SELECT h.ip AS host, p.port AS port, p.proto AS proto,
               s.serviceName AS serviceName, s.vendor AS vendor, s.product AS product,
               s.version AS version, s.cpe AS cpe, s.distro AS distro, s.distroRelease AS distroRelease,
               s.distroPackage AS distroPackage, s.distroPkgVersion AS distroPkgVersion,
               f.banner AS banner, f.httpServer AS httpServer, f.httpPoweredBy AS httpPoweredBy,
               f.tlsSubject AS tlsSubject, f.tlsIssuer AS tlsIssuer, f.tlsNotAfter AS tlsNotAfter
        FROM services s
        INNER JOIN ports p ON s.portId = p.id
        INNER JOIN hosts h ON p.hostId = h.id
        LEFT JOIN fingerprints f ON f.serviceId = s.id
        WHERE h.scanId = :scanId
        ORDER BY h.ip, p.port
        """,
    )
    fun observationRows(scanId: Long): Flow<List<ObservationRow>>

    @Query("DELETE FROM scans WHERE id = :id")
    suspend fun deleteScan(id: Long)
}

/** Flat projection of a fingerprinted service joined up to its host + port. */
data class ObservationRow(
    val host: String,
    val port: Int,
    val proto: String,
    val serviceName: String?,
    val vendor: String?,
    val product: String?,
    val version: String?,
    val cpe: String?,
    val distro: String?,
    val distroRelease: String?,
    val distroPackage: String?,
    val distroPkgVersion: String?,
    val banner: String?,
    val httpServer: String?,
    val httpPoweredBy: String?,
    val tlsSubject: String?,
    val tlsIssuer: String?,
    val tlsNotAfter: String?,
)
