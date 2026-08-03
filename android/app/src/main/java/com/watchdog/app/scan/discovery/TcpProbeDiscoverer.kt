package com.watchdog.app.scan.discovery

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.SocketProbe
import com.watchdog.app.scan.PortState
import com.watchdog.app.scan.enumeration.PortSets
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * The reliable non-root primary. For every candidate IP in the subnet, probe a
 * small liveness set: a completed handshake (OPEN) always proves a host is alive
 * and is streamed immediately. A refused (RST/CLOSED) answer usually proves it
 * too — EXCEPT on networks that fabricate RSTs for dead addresses (phone
 * hotspots, carrier-grade NAT, Windows ICS). Those refusals can be sparse,
 * per-port, and rate-limited, so no small up-front sample catches them reliably.
 *
 * Instead we judge from the whole pass: refused-only hosts are held back, and if
 * an implausible share of the subnet "refused", the RST signal is treated as
 * spoofed and dropped wholesale. OPEN hosts and the other discoverers still
 * stand. Bounded by a Semaphore so we never exceed the socket fan-out budget.
 */
class TcpProbeDiscoverer(
    private val probe: suspend (ip: String, port: Int, timeoutMs: Int) -> PortState = SocketProbe::probe,
) : HostDiscoverer {
    override val source = "tcp"

    override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = channelFlow {
        val gate = Semaphore(config.maxConcurrentSockets)
        val refusedOnly = ConcurrentLinkedQueue<DiscoveredHost>()
        coroutineScope {
            for (ip in cidr.hosts()) {
                launch {
                    gate.withPermit {
                        when (val life = classify(ip, config)) {
                            is Liveness.Open ->
                                send(DiscoveredHost(ip = ip, source = source, serviceHints = life.hints))
                            is Liveness.Refused ->
                                refusedOnly.add(DiscoveredHost(ip = ip, source = source, serviceHints = life.hints))
                            Liveness.Dead -> {}
                        }
                    }
                }
            }
        }
        // A refused (RST) answer only proves a live host when the network isn't
        // fabricating RSTs for dead addresses. If too much of the subnet
        // "refused", the whole RST signal is spoofed — drop it and keep only the
        // real handshakes already streamed.
        if (refusedOnly.size <= maxTrustedRefused(cidr.hostCount)) {
            for (host in refusedOnly) send(host)
        }
    }

    private sealed interface Liveness {
        data class Open(val hints: List<String>) : Liveness
        data class Refused(val hints: List<String>) : Liveness
        data object Dead : Liveness
    }

    /**
     * Probe the liveness ports in order. A single OPEN wins outright (real host);
     * otherwise the first refusal is remembered but we keep looking for an OPEN,
     * so a genuinely-open host is never misfiled as merely refused.
     */
    private suspend fun classify(ip: String, config: ScanConfig): Liveness {
        var refusedHint: String? = null
        var refused = false
        for (port in PortSets.LIVENESS) {
            when (probe(ip, port, config.discoveryProbeTimeoutMs)) {
                PortState.OPEN -> return Liveness.Open(listOfNotNull(PortSets.serviceHint(port)))
                PortState.CLOSED -> if (!refused) {
                    refused = true
                    refusedHint = PortSets.serviceHint(port)
                }
                PortState.FILTERED -> {}
            }
        }
        return if (refused) Liveness.Refused(listOfNotNull(refusedHint)) else Liveness.Dead
    }

    /**
     * How many refused-only hosts are still credible before we call the network a
     * liar. Real LANs answer RST from a handful of firewalled devices at most; a
     * spoofing network refuses across a large slice of the address space.
     */
    private fun maxTrustedRefused(hostCount: Long): Int =
        maxOf(REFUSED_FLOOR, (hostCount / REFUSED_DIVISOR).toInt())

    private companion object {
        // Trust up to this many refused-only hosts outright (covers a normal LAN's
        // firewalled devices on small subnets); above it, scale with subnet size.
        const val REFUSED_FLOOR = 12
        const val REFUSED_DIVISOR = 16
    }
}
