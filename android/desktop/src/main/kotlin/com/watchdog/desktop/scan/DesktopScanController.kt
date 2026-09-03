package com.watchdog.desktop.scan

import com.watchdog.app.correlate.direct.DirectOsvCorrelator
import com.watchdog.app.net.NetworkContext
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.ScanEvent
import com.watchdog.app.scan.ScanPhase
import com.watchdog.app.scan.ScanScope
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.discovery.ReachabilityDiscoverer
import com.watchdog.app.scan.discovery.TcpProbeDiscoverer
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.service.ScanRunState
import com.watchdog.app.service.ScanStateHolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Desktop equivalent of the Android ScanController. Drives the shared [ScanEngine]
 * and folds its events into the shared, in-core [ScanStateHolder] — the same live
 * state model the Android UI uses — minus Room persistence (desktop persistence is
 * a later phase). One run at a time; starting a new run cancels the old.
 */
class DesktopScanController(
    private val scope: CoroutineScope,
    private val networkContext: NetworkContext,
) {
    private val engine = ScanEngine(
        discoverers = listOf(TcpProbeDiscoverer(), ReachabilityDiscoverer()),
    )

    private var job: Job? = null

    /** Correlation output, shown on demand. */
    data class VulnResult(val findings: List<Finding>, val suppressed: List<Finding>)

    private val _vuln = MutableStateFlow<VulnResult?>(null)
    val vuln: StateFlow<VulnResult?> = _vuln.asStateFlow()

    private val _busyMessage = MutableStateFlow<String?>(null)
    val busyMessage: StateFlow<String?> = _busyMessage.asStateFlow()

    val state: StateFlow<ScanRunState> = ScanStateHolder.state

    /** Discover live hosts on the current LAN, then wait for the user to pick some. */
    fun startDiscovery(config: ScanConfig) {
        job?.cancel()
        _vuln.value = null
        val net = networkContext.current()
        val cidr = net?.cidr
        if (cidr == null) {
            ScanStateHolder.update {
                it.copy(failureMessage = "No active IPv4 LAN. Connect to a network and retry.", finished = true, running = false)
            }
            return
        }
        ScanStateHolder.reset(scanId = 0L, scope = ScanScope.WHOLE_NETWORK)
        ScanStateHolder.update { it.copy(phase = ScanPhase.DISCOVERING) }
        job = scope.launch {
            try {
                val seen = mutableSetOf<String>()
                net.gatewayIp?.let { gw ->
                    if (seen.add(gw)) ScanStateHolder.update { s ->
                        s.copy(discoveredHosts = s.discoveredHosts + DiscoveredHost(ip = gw, hostname = "gateway", source = "gateway"))
                    }
                }
                engine.discoverHosts(cidr, config).collect { host ->
                    if (seen.add(host.ip)) ScanStateHolder.update { s ->
                        s.copy(discoveredHosts = s.discoveredHosts + host)
                    }
                }
                ScanStateHolder.update { it.copy(running = false, awaitingHostPick = true) }
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Exception) {
                ScanStateHolder.update { it.copy(failureMessage = e.message, finished = true, running = false) }
            }
        }
    }

    /** Port-scan + fingerprint the chosen hosts. */
    fun scanHosts(ips: List<String>, config: ScanConfig) {
        job?.cancel()
        _vuln.value = null
        job = scope.launch {
            try {
                ScanStateHolder.update {
                    it.copy(
                        running = true, finished = false, cancelled = false, awaitingHostPick = false,
                        currentHost = null, hostsTotal = ips.size, hostsDone = 0,
                        openPortsByHost = emptyMap(), services = emptyList(),
                    )
                }
                engine.scan(ips, config).collect { ev -> fold(ev) }
                ScanStateHolder.update { it.copy(finished = true, running = false) }
            } catch (ce: CancellationException) {
                ScanStateHolder.update { it.copy(cancelled = true, running = false, finished = true) }
                throw ce
            } catch (e: Exception) {
                ScanStateHolder.update { it.copy(failureMessage = e.message, running = false, finished = true) }
            }
        }
    }

    /** Correlate the enumerated services against OSV/KEV/EPSS on-device. */
    fun correlate() {
        val observations = ScanStateHolder.current().services
        if (observations.isEmpty()) return
        scope.launch {
            _busyMessage.value = "Correlating against OSV/KEV/EPSS…"
            try {
                val response = DirectOsvCorrelator().correlate(observations)
                _vuln.value = VulnResult(response.findings, response.suppressed)
            } catch (e: Exception) {
                _vuln.value = VulnResult(emptyList(), emptyList())
                ScanStateHolder.update { it.copy(errors = it.errors + "correlate: ${e.message}") }
            } finally {
                _busyMessage.value = null
            }
        }
    }

    fun cancel() {
        job?.cancel()
        ScanStateHolder.update { it.copy(running = false, finished = true, cancelled = true) }
    }

    fun reset() {
        job?.cancel()
        _vuln.value = null
        ScanStateHolder.update { ScanRunState() }
    }

    private fun fold(ev: ScanEvent) {
        when (ev) {
            is ScanEvent.Phase -> ScanStateHolder.update { it.copy(phase = ev.phase) }
            is ScanEvent.HostStarted -> ScanStateHolder.update { it.copy(currentHost = ev.ip) }
            is ScanEvent.PortOpen -> ScanStateHolder.update { s ->
                val existing = s.openPortsByHost[ev.ip].orEmpty()
                s.copy(openPortsByHost = s.openPortsByHost + (ev.ip to (existing + ev.port)))
            }
            is ScanEvent.ServiceFound -> ScanStateHolder.update { it.copy(services = it.services + ev.observation) }
            is ScanEvent.HostFinished -> ScanStateHolder.update { it.copy(hostsDone = it.hostsDone + 1) }
            is ScanEvent.Failed -> ScanStateHolder.update { it.copy(errors = it.errors + "${ev.where}: ${ev.message}") }
            else -> {}
        }
    }
}
