package com.watchdog.app.correlate

import com.watchdog.app.scan.model.CorrelateResponse
import com.watchdog.app.scan.model.ServiceObservation

/**
 * Takes the evidence the phone collected and returns prioritized findings.
 * Two implementations: DirectOsvCorrelator (on-device, OSV+KEV+EPSS) and
 * RemoteCorrelator (POST to the user's own backend). Selected at runtime from
 * settings.
 */
interface Correlator {
    suspend fun correlate(observations: List<ServiceObservation>): CorrelateResponse
}
