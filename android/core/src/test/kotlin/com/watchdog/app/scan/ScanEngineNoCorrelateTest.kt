package com.watchdog.app.scan

import com.watchdog.app.scan.enumeration.PortScanner
import com.watchdog.app.scan.fingerprint.Fingerprinter
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanEngineNoCorrelateTest {
    @Test
    fun `scan emits no Correlated event`() = runTest {
        // Empty host list: the pipeline runs to completion without touching the network.
        val engine = ScanEngine(
            discoverers = emptyList(),
            portScanner = PortScanner(),
            fingerprinter = Fingerprinter(),
        )
        val events = engine.scan(emptyList(), ScanConfig(scope = ScanScope.SINGLE_HOST)).toList()
        assertTrue(events.none { it is ScanEvent.Correlated })
        assertTrue(events.any { it is ScanEvent.Done })
    }
}
