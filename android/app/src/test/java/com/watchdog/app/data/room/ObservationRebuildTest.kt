package com.watchdog.app.data.room

import org.junit.Assert.assertEquals
import org.junit.Test

class ObservationRebuildTest {
    @Test
    fun `row maps to observation with product and evidence`() {
        val row = ObservationRow(
            host = "192.168.1.5", port = 22, proto = "tcp", serviceName = "ssh",
            vendor = "openbsd", product = "openssh", version = "8.2p1", cpe = null,
            distro = "ubuntu", distroRelease = "focal", distroPackage = null, distroPkgVersion = "1:8.2p1-4",
            banner = "SSH-2.0-OpenSSH_8.2p1", httpServer = null, httpPoweredBy = null, httpTitle = null,
            tlsSubject = null, tlsIssuer = null, tlsNotAfter = null,
        )
        val obs = ScanRepository.rowToObservation(row)
        assertEquals("192.168.1.5", obs.host)
        assertEquals(22, obs.port)
        assertEquals("openssh", obs.product?.product)
        assertEquals("8.2p1", obs.product?.version)
        assertEquals("SSH-2.0-OpenSSH_8.2p1", obs.evidence?.banner)
    }

    @Test
    fun `null product yields null ProductIdentity`() {
        val row = ObservationRow(
            host = "10.0.0.9", port = 80, proto = "tcp", serviceName = "http",
            vendor = null, product = null, version = null, cpe = null,
            distro = null, distroRelease = null, distroPackage = null, distroPkgVersion = null,
            banner = null, httpServer = "nginx", httpPoweredBy = null, httpTitle = null,
            tlsSubject = null, tlsIssuer = null, tlsNotAfter = null,
        )
        val obs = ScanRepository.rowToObservation(row)
        assertEquals(null, obs.product)
        assertEquals("nginx", obs.evidence?.httpServer)
    }
}
