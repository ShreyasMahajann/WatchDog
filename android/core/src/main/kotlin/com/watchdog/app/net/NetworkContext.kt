package com.watchdog.app.net

import kotlinx.coroutines.flow.Flow

/** The network the device is currently joined to and can actually scan. */
data class NetworkInfo(
    val ssid: String?, // null if unknown / no permission
    val cidr: Cidr?, // null if no IPv4 link found
    val localIp: String?, // the device's own address on this LAN
    val gatewayIp: String?,
    val isWifi: Boolean,
)

interface NetworkContext {
    /** The active network, or null if offline / no IPv4. */
    fun current(): NetworkInfo?

    /**
     * Emits (conflated) whenever the default network changes — joined, dropped,
     * or its link properties/capabilities shift. Callers re-read [current] on each
     * emission. The stream is hot for as long as it's collected.
     */
    fun changes(): Flow<Unit>
}
