package com.watchdog.app.devicewatch.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * One device Device Watch has seen on a given network. Identity is (scopeKey, ip): non-root Android
 * exposes no MAC address, so the LAN IP is the only stable per-network handle we have. A device that
 * changes DHCP lease will surface as a new row — that limitation is stated in the UI.
 *
 * Denormalized on purpose: the list and detail screens show exactly these fields. `present` reflects
 * whether the device was seen in the most recent scan of its scope; a device that drops off is kept
 * (flipped to present=false), never deleted.
 */
@Entity(
    tableName = "watched_devices",
    indices = [
        Index(value = ["scopeKey", "ip"], unique = true),
        Index(value = ["scopeKey"]),
    ],
)
data class WatchedDeviceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** Per-network identity, matching NetScan's network id: "ssid|networkAddr/prefix". */
    val scopeKey: String,
    /** Human-readable network name for display (SSID, else dotted CIDR). */
    val networkLabel: String,
    val ip: String,
    val hostname: String?,
    /** Comma-joined mDNS/service hints, "" if none. */
    val serviceHints: String,
    /** User-given name, null if unnamed. */
    val label: String?,
    /** Whether the user has marked this device as known/trusted. New devices start untrusted. */
    val trusted: Boolean,
    val firstSeen: Long,
    val lastSeen: Long,
    /** Seen in the most recent scan of this scope. */
    val present: Boolean,
)
