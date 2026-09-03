package com.watchdog.desktop.scan

import com.watchdog.app.correlate.Correlator
import com.watchdog.app.correlate.direct.DirectOsvCorrelator
import com.watchdog.app.correlate.remote.RemoteCorrelator
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
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.SettingsStore
import com.watchdog.app.service.ScanRunState
import com.watchdog.app.service.ScanStateHolder
import com.watchdog.desktop.data.DesktopScanStore
import com.watchdog.desktop.data.HostRec
import com.watchdog.desktop.data.ScanRecord
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Desktop equivalent of the Android ScanController. Drives the shared [ScanEngine],
 * folds its events into the shared in-core [ScanStateHolder], and persists scans to
 * the [DesktopScanStore]. Correlator is chosen from [SettingsStore] (OSV or the
 * user's own server), matching Android.
 */
class DesktopScanController(
    private val scope: CoroutineScope,
    private val networkContext: NetworkContext,
    private val scanStore: DesktopScanStore,
    private val settingsStore: SettingsStore,
) {
    private val engine = ScanEngine(
        discoverers = listOf(TcpProbeDiscoverer(), ReachabilityDiscoverer()),
    )

    private var job: Job? = null
    private var currentScanId: Long? = null

    data class VulnResult(val findings: List<Finding>, val suppressed: List<Finding>)

    private val _vuln = MutableStateFlow<VulnResult?>(null)
    val vuln: StateFlow<VulnResult?> = _vuln.asStateFlow()

    private val _busyMessage = MutableStateFlow<String?>(null)
    val busyMessage: StateFlow<String?> = _busyMessage.asStateFlow()

    private val _historyVersion = MutableStateFlow(0)
    /** Increments whenever the persisted history changes, so the UI can re-list. */
    val historyVersion: StateFlow<Int> = _historyVersion.asStateFlow()

    val state: StateFlow<ScanRunState> = ScanStateHolder.state

    fun startDiscovery(config: ScanConfig) {
        job?.cancel()
        _vuln.value = null
        currentScanId = null
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

    fun scanHosts(ips: List<String>, config: ScanConfig) {
        job?.cancel()
        _vuln.value = null
        val net = networkContext.current() ?: return
        job = scope.launch {
            val scanId = withContext(NonCancellable) { scanStore.startScan(net, config) }
            currentScanId = scanId
            bumpHistory()
            try {
                ScanStateHolder.update {
                    it.copy(
                        scanId = scanId,
                        running = true, finished = false, cancelled = false, awaitingHostPick = false,
                        currentHost = null, hostsTotal = ips.size, hostsDone = 0,
                        openPortsByHost = emptyMap(), services = emptyList(),
                    )
                }
                engine.scan(ips, config).collect { ev -> fold(ev) }
                persist(scanId, "DONE")
                ScanStateHolder.update { it.copy(finished = true, running = false) }
            } catch (ce: CancellationException) {
                persist(scanId, "CANCELLED")
                ScanStateHolder.update { it.copy(cancelled = true, running = false, finished = true) }
                throw ce
            } catch (e: Exception) {
                persist(scanId, "ERROR")
                ScanStateHolder.update { it.copy(failureMessage = e.message, running = false, finished = true) }
            }
        }
    }

    fun correlate() {
        val observations = ScanStateHolder.current().services
        if (observations.isEmpty()) return
        scope.launch {
            _busyMessage.value = "Correlating against OSV/KEV/EPSS…"
            try {
                val response = correlator().correlate(observations)
                _vuln.value = VulnResult(response.findings, response.suppressed)
                currentScanId?.let { scanStore.saveFindings(it, response.findings + response.suppressed); bumpHistory() }
            } catch (e: Exception) {
                _vuln.value = VulnResult(emptyList(), emptyList())
                ScanStateHolder.update { it.copy(errors = it.errors + "correlate: ${e.message}") }
            } finally {
                _busyMessage.value = null
            }
        }
    }

    /** Load a saved scan into the live view (read-only browse from history). */
    fun openHistory(record: ScanRecord) {
        job?.cancel()
        currentScanId = record.summary.id
        ScanStateHolder.update {
            ScanRunState(
                scanId = record.summary.id,
                discoveredHosts = record.hosts.map { h -> DiscoveredHost(ip = h.ip, hostname = h.hostname, source = h.source) },
                services = record.services,
                finished = true,
                running = false,
            )
        }
        val findings = record.findings.filter { !it.suppressed }
        val suppressed = record.findings.filter { it.suppressed }
        _vuln.value = if (record.findings.isEmpty()) null else VulnResult(findings, suppressed)
    }

    fun renameScan(id: Long, name: String?) { scanStore.rename(id, name?.trim()?.ifBlank { null }); bumpHistory() }
    fun deleteScan(id: Long) { scanStore.delete(id); if (currentScanId == id) reset(); bumpHistory() }

    fun cancel() {
        job?.cancel()
        ScanStateHolder.update { it.copy(running = false, finished = true, cancelled = true) }
    }

    fun reset() {
        job?.cancel()
        _vuln.value = null
        currentScanId = null
        ScanStateHolder.update { ScanRunState() }
    }

    private suspend fun persist(scanId: Long, status: String) {
        val s = ScanStateHolder.current()
        val hosts = s.discoveredHosts.map { HostRec(it.ip, it.hostname, it.source) }
        withContext(NonCancellable) { scanStore.finishScan(scanId, status, hosts, s.services) }
        bumpHistory()
    }

    private suspend fun correlator(): Correlator {
        val s = settingsStore.settings.first()
        return if (s.correlatorMode == CorrelatorMode.OWN_SERVER && s.serverBaseUrl.isNotBlank()) {
            RemoteCorrelator(baseUrl = s.serverBaseUrl, token = s.serverToken.ifBlank { null })
        } else {
            DirectOsvCorrelator()
        }
    }

    private fun bumpHistory() { _historyVersion.value = _historyVersion.value + 1 }

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
