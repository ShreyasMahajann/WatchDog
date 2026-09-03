package com.watchdog.app.devicewatch

import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkInfo

/**
 * Per-network identity for Device Watch. The scope key matches NetScan's network id
 * (`ScanRepository.startScan`) so the two tools agree on what "the same network" means:
 * "ssid|networkAddr/prefix". Pure — no android.* imports, so it's JVM-unit-testable.
 */
object WatchScope {

    /** Stable key for the network's device baseline, or null if there's no usable IPv4 subnet. */
    fun of(net: NetworkInfo): String? {
        val cidr = net.cidr ?: return null
        return "${net.ssid ?: "net"}|${cidr.networkAddr}/${cidr.prefixLength}"
    }

    /** Human-readable name for the network (SSID, else dotted CIDR, else a generic fallback). */
    fun label(net: NetworkInfo): String {
        net.ssid?.let { return it }
        val cidr = net.cidr ?: return "network"
        return "${Cidr.longToIp(cidr.networkAddr)}/${cidr.prefixLength}"
    }
}
