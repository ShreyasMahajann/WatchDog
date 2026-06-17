package com.watchdog.app.scan

/** How deep the port enumeration goes on a selected host. */
enum class ScanDepth(val label: String, val estimate: String) {
    TOP_100("Top 100 ports", "seconds"),
    TOP_1000("Top 1000 ports", "~1 min/host"),
    FULL("All 65535 ports", "several min/host"),
}

/** Whole network (auto-scan every live host) vs a single chosen host. */
enum class ScanScope { WHOLE_NETWORK, SINGLE_HOST }

data class ScanConfig(
    val scope: ScanScope,
    val depth: ScanDepth = ScanDepth.TOP_1000,
    // Bounded socket fan-out. Stays well under the app's fd ceiling.
    val maxConcurrentSockets: Int = 192,
    val discoveryProbeTimeoutMs: Int = 300,
    val portConnectTimeoutMs: Int = 600,
    val bannerReadTimeoutMs: Int = 1500,
    // Refuse to enumerate a subnet wider than this without explicit opt-in.
    val allowLargeSubnet: Boolean = false,
)
