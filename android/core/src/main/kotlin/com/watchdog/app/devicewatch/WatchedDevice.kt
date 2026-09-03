package com.watchdog.app.devicewatch

/**
 * One device Device Watch has seen on a given network. Pure model shared by both
 * apps; each platform maps its own storage rows (Android Room entity, desktop
 * sqlite row) to/from this. Identity is (scopeKey, ip): non-root/desktop LAN
 * scanning exposes no stable MAC, so the IP is the per-network handle.
 */
data class WatchedDevice(
    val id: Long = 0,
    /** Per-network identity: "ssid|networkAddr/prefix" (matches NetScan's network id). */
    val scopeKey: String,
    /** Human-readable network name (SSID, else dotted CIDR). */
    val networkLabel: String,
    val ip: String,
    val hostname: String?,
    /** Comma-joined mDNS/service hints, "" if none. */
    val serviceHints: String,
    /** User-given name, null if unnamed. */
    val label: String?,
    /** Whether the user marked this device known/trusted. New devices start untrusted. */
    val trusted: Boolean,
    val firstSeen: Long,
    val lastSeen: Long,
    /** Seen in the most recent scan of this scope. */
    val present: Boolean,
)
