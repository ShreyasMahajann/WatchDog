package com.watchdog.app.scan.discovery

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import kotlinx.coroutines.flow.Flow

/** A host found alive on the LAN, with whatever identity the source could add. */
data class DiscoveredHost(
    val ip: String,
    val hostname: String? = null,
    val source: String, // "tcp" | "icmp" | "mdns"
    val serviceHints: List<String> = emptyList(), // e.g. mDNS service types
)

/**
 * One channel for finding live hosts. Implementations are independent and weak
 * on their own; ScanEngine merges them and dedups by IP. Emissions may repeat
 * an IP across sources — the merge layer collapses them.
 */
interface HostDiscoverer {
    val source: String
    fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost>
}
