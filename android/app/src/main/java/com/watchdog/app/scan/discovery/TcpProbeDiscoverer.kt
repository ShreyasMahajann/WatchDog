package com.watchdog.app.scan.discovery

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.SocketProbe
import com.watchdog.app.scan.PortState
import com.watchdog.app.scan.enumeration.PortSets
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * The reliable non-root primary. For every candidate IP in the subnet, probe a
 * tiny liveness set; any OPEN or CLOSED (RST) answer means the host is alive.
 * Bounded by a Semaphore so we never exceed the socket fan-out budget.
 */
class TcpProbeDiscoverer : HostDiscoverer {
    override val source = "tcp"

    override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = channelFlow {
        val gate = Semaphore(config.maxConcurrentSockets)
        coroutineScope {
            for (ip in cidr.hosts()) {
                launch {
                    gate.withPermit {
                        val hit = probeAlive(ip, config)
                        if (hit != null) {
                            send(DiscoveredHost(ip = ip, source = source, serviceHints = hit.hints))
                        }
                    }
                }
            }
        }
    }

    private class AliveHit(val hints: List<String>)

    /** Alive if any liveness port answered (OPEN or refused/CLOSED). */
    private suspend fun probeAlive(ip: String, config: ScanConfig): AliveHit? {
        for (port in PortSets.LIVENESS) {
            val state = SocketProbe.probe(ip, port, config.discoveryProbeTimeoutMs)
            if (state == PortState.OPEN || state == PortState.CLOSED) {
                return AliveHit(listOfNotNull(PortSets.serviceHint(port)))
            }
        }
        return null
    }
}
