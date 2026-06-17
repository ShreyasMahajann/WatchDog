package com.watchdog.app.data.room

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

// On-device scan store. Mirrors the plan's entity chain
// Network -> Scan -> Host -> Port -> Service -> Fingerprint, plus Finding.
// Enums are stored as their name via Converters; timestamps as epoch millis.

@Entity(tableName = "networks")
data class NetworkEntity(
    @PrimaryKey val id: String, // derived from bssid/ssid + cidr
    val ssid: String?,
    val bssid: String?,
    val cidr: String?,
    val gatewayIp: String?,
    val firstSeen: Long,
    val lastSeen: Long,
)

@Entity(
    tableName = "scans",
    foreignKeys = [
        ForeignKey(
            entity = NetworkEntity::class,
            parentColumns = ["id"],
            childColumns = ["networkId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("networkId")],
)
data class ScanEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val networkId: String,
    val scope: String, // ScanScope
    val targetHost: String?,
    val depth: String, // ScanDepth
    val correlatorMode: String,
    val startedAt: Long,
    val finishedAt: Long?,
    val status: String, // RUNNING | DONE | CANCELLED | ERROR
)

@Entity(
    tableName = "hosts",
    foreignKeys = [
        ForeignKey(
            entity = ScanEntity::class,
            parentColumns = ["id"],
            childColumns = ["scanId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("scanId")],
)
data class HostEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanId: Long,
    val ip: String,
    val hostname: String?,
    val discoverySources: String, // comma-separated
    val osGuess: String?,
    val reachable: Boolean,
)

@Entity(
    tableName = "ports",
    foreignKeys = [
        ForeignKey(
            entity = HostEntity::class,
            parentColumns = ["id"],
            childColumns = ["hostId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("hostId")],
)
data class PortEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val hostId: Long,
    val port: Int,
    val proto: String,
    val state: String, // PortState
)

@Entity(
    tableName = "services",
    foreignKeys = [
        ForeignKey(
            entity = PortEntity::class,
            parentColumns = ["id"],
            childColumns = ["portId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("portId")],
)
data class ServiceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val portId: Long,
    val serviceName: String?,
    val vendor: String?,
    val product: String?,
    val version: String?,
    val cpe: String?,
    val distro: String?,
    val distroRelease: String?,
    val distroPackage: String?,
    val distroPkgVersion: String?,
)

@Entity(
    tableName = "fingerprints",
    foreignKeys = [
        ForeignKey(
            entity = ServiceEntity::class,
            parentColumns = ["id"],
            childColumns = ["serviceId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("serviceId")],
)
data class FingerprintEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val serviceId: Long,
    val banner: String?,
    val httpServer: String?,
    val httpPoweredBy: String?,
    val tlsSubject: String?,
    val tlsIssuer: String?,
    val tlsNotAfter: String?,
    val probedAt: Long,
)

@Entity(
    tableName = "findings",
    foreignKeys = [
        ForeignKey(
            entity = ScanEntity::class,
            parentColumns = ["id"],
            childColumns = ["scanId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("scanId")],
)
data class FindingEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanId: Long,
    val host: String,
    val port: Int,
    val productJson: String,
    val cveId: String,
    val state: String,
    val matchBasis: String,
    val confidence: Int,
    val severity: String,
    val cvssScore: Double?,
    val cvssVersion: String?,
    val knownExploited: Boolean,
    val epss: Double?,
    val exploitMaturity: String,
    val priority: Int,
    val whyJson: String,
    val remediation: String?,
    val suppressed: Boolean,
    val suppressionReason: String?,
)
