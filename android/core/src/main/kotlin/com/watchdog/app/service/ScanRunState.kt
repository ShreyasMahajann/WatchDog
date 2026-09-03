package com.watchdog.app.service

import com.watchdog.app.scan.ScanPhase
import com.watchdog.app.scan.ScanScope
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation

/** The live state of a running (or finished) scan. Held in a process singleton. */
data class ScanRunState(
    val scanId: Long? = null,
    val scope: ScanScope? = null,
    val phase: ScanPhase = ScanPhase.DISCOVERING,
    val running: Boolean = false,
    val discoveredHosts: List<DiscoveredHost> = emptyList(),
    val currentHost: String? = null,
    val hostsTotal: Int = 0,
    val hostsDone: Int = 0,
    val openPortsByHost: Map<String, List<Int>> = emptyMap(),
    val services: List<ServiceObservation> = emptyList(),
    val findings: List<Finding> = emptyList(),
    val suppressed: List<Finding> = emptyList(),
    val errors: List<String> = emptyList(),
    val finished: Boolean = false,
    val cancelled: Boolean = false,
    val awaitingHostPick: Boolean = false,
    val failureMessage: String? = null,
) {
    val openPortCount: Int get() = openPortsByHost.values.sumOf { it.size }
}
