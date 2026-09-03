package com.watchdog.app.scan

import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.model.CorrelateResponse
import com.watchdog.app.scan.model.ServiceObservation

/** Coarse phase of a running scan, for the progress UI. */
enum class ScanPhase { DISCOVERING, ENUMERATING, FINGERPRINTING, CORRELATING, DONE }

/** Streamed as a scan progresses. The controller folds these into UI state + Room. */
sealed interface ScanEvent {
    data class Phase(val phase: ScanPhase) : ScanEvent
    data class HostDiscovered(val host: DiscoveredHost) : ScanEvent
    data class HostStarted(val ip: String) : ScanEvent
    data class PortOpen(val ip: String, val port: Int, val serviceHint: String?) : ScanEvent
    data class ServiceFound(val observation: ServiceObservation) : ScanEvent
    data class HostFinished(val ip: String, val openPorts: Int) : ScanEvent
    data class Correlated(val response: CorrelateResponse) : ScanEvent
    data class Failed(val where: String, val message: String) : ScanEvent
    data object Done : ScanEvent
}
