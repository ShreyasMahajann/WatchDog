package com.watchdog.app.scan

import com.watchdog.app.correlate.Correlator
import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.discovery.HostDiscoverer
import com.watchdog.app.scan.enumeration.PortScanner
import com.watchdog.app.scan.enumeration.PortSets
import com.watchdog.app.scan.fingerprint.Fingerprinter
import com.watchdog.app.scan.model.ServiceObservation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.merge
import java.util.concurrent.ConcurrentHashMap

/**
 * The on-device scan pipeline: discover live hosts, enumerate their ports,
 * fingerprint each open service, then correlate. Runs on whatever scope its
 * caller drives — whole-network (scan every discovered host) or single-host
 * (scan one chosen IP).
 *
 * Per-host and per-service failures are isolated: they emit a Failed event and
 * the scan continues. Cancellation propagates cooperatively through the
 * coroutine scope of whoever collects the returned flow.
 */
class ScanEngine(
    private val discoverers: List<HostDiscoverer>,
    private val portScanner: PortScanner = PortScanner(),
    private val fingerprinter: Fingerprinter = Fingerprinter(),
) {

    /** Merged, de-duplicated live-host discovery across all sources. */
    fun discoverHosts(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = channelFlow {
        val seen = ConcurrentHashMap.newKeySet<String>()
        val merged = merge(*discoverers.map { it.discover(cidr, config) }.toTypedArray())
        merged.collect { host ->
            if (seen.add(host.ip)) send(host)
        }
    }

    /**
     * Enumerate + fingerprint each host in [hosts], then correlate all findings.
     * [hosts] is the explicit target set: the full discovered list for a
     * whole-network scan, or a single IP for a single-host deep scan.
     */
    fun scan(
        hosts: List<String>,
        config: ScanConfig,
        correlator: Correlator,
    ): Flow<ScanEvent> = channelFlow {
        val observations = mutableListOf<ServiceObservation>()

        send(ScanEvent.Phase(ScanPhase.ENUMERATING))
        val ports = PortSets.forDepth(config.depth)

        for (ip in hosts) {
            currentCoroutineContext().ensureActive()
            send(ScanEvent.HostStarted(ip))
            var openCount = 0
            try {
                portScanner.scan(ip, ports, config).collect { open ->
                    openCount++
                    send(ScanEvent.PortOpen(ip, open.port, open.serviceHint))
                    try {
                        val obs = fingerprinter.fingerprint(ip, open.port, config)
                        observations.add(obs)
                        send(ScanEvent.ServiceFound(obs))
                    } catch (ce: CancellationException) {
                        throw ce
                    } catch (e: Exception) {
                        send(ScanEvent.Failed("fingerprint $ip:${open.port}", e.message ?: e.toString()))
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Exception) {
                send(ScanEvent.Failed("portscan $ip", e.message ?: e.toString()))
            }
            send(ScanEvent.HostFinished(ip, openCount))
        }

        send(ScanEvent.Phase(ScanPhase.CORRELATING))
        try {
            val response = correlator.correlate(observations)
            send(ScanEvent.Correlated(response))
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            send(ScanEvent.Failed("correlate", e.message ?: e.toString()))
        }

        send(ScanEvent.Phase(ScanPhase.DONE))
        send(ScanEvent.Done)
    }
}
