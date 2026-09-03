package com.watchdog.app.scan

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.discovery.HostDiscoverer
import com.watchdog.app.scan.enumeration.PortScanner
import com.watchdog.app.scan.enumeration.PortSets
import com.watchdog.app.scan.fingerprint.Fingerprinter
import com.watchdog.app.scan.identity.IdentityProbe
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
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
    private val identityProbes: List<IdentityProbe> = emptyList(),
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
     * Enumerate + fingerprint each host in [hosts]. Correlation is no longer part
     * of the scan — it runs on demand per device (see CorrelatorFactory). [hosts]
     * is the explicit target set the caller chose (any subset of discovered IPs).
     */
    fun scan(
        hosts: List<String>,
        config: ScanConfig,
    ): Flow<ScanEvent> = channelFlow {
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

            // UDP identity probes — best-effort device naming for hosts that expose
            // no fingerprintable TCP service. Run concurrently; failures are silent.
            if (config.identityProbes && identityProbes.isNotEmpty()) {
                try {
                    val found = coroutineScope {
                        identityProbes.map { probe -> async { runCatching { probe.probe(ip, config) }.getOrNull() } }.awaitAll()
                    }
                    for (obs in found) {
                        if (obs != null) {
                            openCount++
                            send(ScanEvent.PortOpen(ip, obs.port, obs.serviceName))
                            send(ScanEvent.ServiceFound(obs))
                        }
                    }
                } catch (ce: CancellationException) {
                    throw ce
                } catch (e: Exception) {
                    send(ScanEvent.Failed("identity $ip", e.message ?: e.toString()))
                }
            }

            send(ScanEvent.HostFinished(ip, openCount))
        }

        send(ScanEvent.Phase(ScanPhase.DONE))
        send(ScanEvent.Done)
    }
}
