package com.watchdog.app.scan.discovery

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.SocketProbe
import com.watchdog.app.scan.PortState
import com.watchdog.app.scan.enumeration.PortSets
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The reliable non-root primary. For every candidate IP in the subnet, probe a
 * tiny liveness set; a real handshake (OPEN) always proves the host is alive,
 * and a refused (RST/CLOSED) answer does too — EXCEPT on networks that fabricate
 * RSTs for dead addresses (phone hotspots, carrier-grade NAT, Windows ICS), where
 * "refused" would flag much of the subnet as alive. A calibration probe over the
 * same liveness ports detects those networks up front and, when found, trusts
 * only OPEN. Bounded by a Semaphore so we never exceed the socket fan-out budget.
 */
class TcpProbeDiscoverer(
    private val probe: suspend (ip: String, port: Int, timeoutMs: Int) -> PortState = SocketProbe::probe,
) : HostDiscoverer {
    override val source = "tcp"

    override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = channelFlow {
        val gate = Semaphore(config.maxConcurrentSockets)
        // On RST-spoofing networks a refused connection is meaningless, so fall
        // back to trusting only a completed handshake.
        val trustRefused = !refusesEveryAddress(cidr, gate)
        coroutineScope {
            for (ip in cidr.hosts()) {
                launch {
                    gate.withPermit {
                        val hit = probeAlive(ip, config, trustRefused)
                        if (hit != null) {
                            send(DiscoveredHost(ip = ip, source = source, serviceHints = hit.hints))
                        }
                    }
                }
            }
        }
    }

    private class AliveHit(val hints: List<String>)

    /**
     * Alive if any liveness port completed a handshake (OPEN); also alive on a
     * refused (CLOSED) answer, but only when [trustRefused] — see the class doc.
     */
    private suspend fun probeAlive(ip: String, config: ScanConfig, trustRefused: Boolean): AliveHit? {
        for (port in PortSets.LIVENESS) {
            when (probe(ip, port, config.discoveryProbeTimeoutMs)) {
                PortState.OPEN -> return AliveHit(listOfNotNull(PortSets.serviceHint(port)))
                PortState.CLOSED -> if (trustRefused) return AliveHit(listOfNotNull(PortSets.serviceHint(port)))
                PortState.FILTERED -> {}
            }
        }
        return null
    }

    /**
     * Probe a spread of addresses that can't plausibly all be real hosts. If a
     * majority answer "connection refused" (RST) without a single genuine open
     * port, the network is fabricating RSTs for dead addresses, so a refused
     * connection can't be trusted as proof of life. A normal LAN silently drops
     * connections to dead addresses, so these samples stay quiet and the signal
     * is preserved.
     *
     * Calibration probes the SAME liveness ports discovery trusts — otherwise a
     * network that only RSTs on, say, 445 (Windows ICS hotspots do exactly this)
     * slips past calibration yet still flags every dead address alive in the main
     * pass. A generous timeout is used so a slow RST is seen as CLOSED, not lost.
     */
    private suspend fun refusesEveryAddress(cidr: Cidr, gate: Semaphore): Boolean {
        val samples = calibrationAddresses(cidr)
        if (samples.size < MIN_CALIBRATION_SAMPLES) return false
        val refused = AtomicInteger(0)
        coroutineScope {
            for (ip in samples) {
                launch {
                    gate.withPermit {
                        if (refusesSample(ip)) refused.incrementAndGet()
                    }
                }
            }
        }
        // Strict majority of the spread refused with no real open port → spoofing.
        return refused.get() * 2 > samples.size
    }

    /**
     * True if the sample answers RST on any liveness port and never opens one —
     * i.e. the discovery rule would wrongly call this (probably-dead) address
     * alive. Ports are probed concurrently so the whole check costs one timeout.
     */
    private suspend fun refusesSample(ip: String): Boolean = coroutineScope {
        val states = PortSets.LIVENESS.map { port ->
            async { probe(ip, port, CALIBRATION_TIMEOUT_MS) }
        }.awaitAll()
        when {
            states.any { it == PortState.OPEN } -> false // a real host, not evidence of spoofing
            else -> states.any { it == PortState.CLOSED }
        }
    }

    /** Evenly-spread host addresses used only for spoofing calibration. */
    private fun calibrationAddresses(cidr: Cidr): List<String> {
        val count = cidr.hostCount
        if (count < MIN_HOSTS_FOR_CALIBRATION) return emptyList()
        val first = if (cidr.prefixLength >= 31) cidr.networkAddr else cidr.networkAddr + 1
        val addrs = LinkedHashSet<String>()
        for (k in 1..CALIBRATION_SAMPLES) {
            val offset = (count * k) / (CALIBRATION_SAMPLES + 1)
            addrs.add(Cidr.longToIp(first + offset))
        }
        return addrs.toList()
    }

    private companion object {
        // Subnets smaller than this are too sparse to calibrate reliably — just
        // trust refused there (behaves like the original discoverer).
        const val MIN_HOSTS_FOR_CALIBRATION = 8L
        const val CALIBRATION_SAMPLES = 6
        const val MIN_CALIBRATION_SAMPLES = 4
        // Generous vs the per-host discovery timeout so a slow spoofed RST still
        // registers as CLOSED during calibration instead of timing out.
        const val CALIBRATION_TIMEOUT_MS = 800
    }
}
