package com.watchdog.app.scan.discovery

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.PortState
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanScope
import com.watchdog.app.scan.enumeration.PortSets
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpProbeDiscovererTest {

    private val cidr = Cidr.of("10.0.0.0", 24)
    private val config = ScanConfig(scope = ScanScope.WHOLE_NETWORK)

    /**
     * A phone-hotspot / carrier-NAT network: the gateway answers RST (connection
     * refused) for EVERY address, alive or dead. A refused connection therefore
     * proves nothing, so discovery must not report the whole /24 as alive.
     */
    @Test
    fun `network that refuses every address yields no phantom hosts`() = runTest {
        val discoverer = TcpProbeDiscoverer(probe = { _, _, _ -> PortState.CLOSED })
        val found = discoverer.discover(cidr, config).toList()
        assertTrue(
            "RST-spoofing network should not produce phantom hosts, got ${found.size}",
            found.isEmpty(),
        )
    }

    /**
     * A Windows-ICS / hotspot network that fabricates an RST for dead addresses on
     * only ONE liveness port (445, seen in the field) must still be caught: the
     * calibration probes the same liveness ports discovery trusts, so it detects
     * the spoofing and refuses to report the phantoms.
     */
    @Test
    fun `network that only RSTs on port 445 yields no phantom hosts`() = runTest {
        val discoverer = TcpProbeDiscoverer(probe = { _, port, _ ->
            if (port == 445) PortState.CLOSED else PortState.FILTERED
        })
        val found = discoverer.discover(cidr, config).toList()
        assertTrue(
            "445-only RST spoofing should not produce phantom hosts, got ${found.size}",
            found.isEmpty(),
        )
    }

    /**
     * On that same spoofing network, a genuinely-alive host still completes a real
     * TCP handshake (OPEN) on one of its ports, so it must still be discovered.
     */
    @Test
    fun `real open host is still found on a refusing network`() = runTest {
        val realHost = "10.0.0.42"
        val discoverer = TcpProbeDiscoverer(probe = { ip, port, _ ->
            if (ip == realHost && port == 80) PortState.OPEN else PortState.CLOSED
        })
        val found = discoverer.discover(cidr, config).toList()
        assertEquals(listOf(realHost), found.map { it.ip })
    }

    /**
     * A normal LAN drops (FILTERED) connections to dead addresses, so a refused
     * connection there is a legitimate liveness signal — a firewalled host that
     * RSTs but exposes no open port must still be discovered.
     */
    @Test
    fun `refused host on an otherwise-silent network is still alive`() = runTest {
        val firewalled = "10.0.0.99"
        val discoverer = TcpProbeDiscoverer(probe = { ip, port, _ ->
            if (ip == firewalled && port == PortSets.LIVENESS.first()) PortState.CLOSED else PortState.FILTERED
        })
        val found = discoverer.discover(cidr, config).toList()
        assertEquals(listOf(firewalled), found.map { it.ip })
    }
}
