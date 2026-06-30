package com.watchdog.app.service

import android.content.Context
import com.watchdog.app.correlate.Correlator
import com.watchdog.app.correlate.direct.DirectOsvCorrelator
import com.watchdog.app.correlate.remote.RemoteCorrelator
import com.watchdog.app.data.room.ScanRepository
import com.watchdog.app.data.room.WatchDogDatabase
import com.watchdog.app.net.AndroidNetworkContext
import com.watchdog.app.net.NetworkContext
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.ScanEvent
import com.watchdog.app.scan.ScanPhase
import com.watchdog.app.scan.ScanScope
import com.watchdog.app.scan.discovery.MdnsDiscoverer
import com.watchdog.app.scan.discovery.ReachabilityDiscoverer
import com.watchdog.app.scan.discovery.TcpProbeDiscoverer
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.SettingsRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Owns the scan job and folds ScanEvents into both the live ScanStateHolder and
 * the durable Room store. One run at a time; starting a new run cancels the old.
 */
class ScanController(
    appContext: Context,
    private val scope: CoroutineScope,
    private val onTerminal: () -> Unit = {},
) {
    private val ctx = appContext.applicationContext
    private val repo = ScanRepository(WatchDogDatabase.get(ctx).dao())
    private val settingsRepo = SettingsRepository(ctx)
    private val networkContext: NetworkContext = AndroidNetworkContext(ctx)
    private val engine = ScanEngine(
        discoverers = listOf(
            TcpProbeDiscoverer(),
            ReachabilityDiscoverer(),
            MdnsDiscoverer(ctx),
        ),
    )

    private var job: Job? = null
    private val hostIds = mutableMapOf<String, Long>()

    fun startWholeNetwork(config: ScanConfig) = launchRun(ScanScope.WHOLE_NETWORK, config) { scanId, correlator ->
        val hosts = discover(scanId, config)
        ScanStateHolder.update { it.copy(hostsTotal = hosts.size) }
        runScan(scanId, hosts, config, correlator)
    }

    /** Single-host branch: discover the host list, then stop for the user to pick. */
    fun startDiscovery(config: ScanConfig) = launchRun(ScanScope.SINGLE_HOST, config) { scanId, _ ->
        discover(scanId, config)
        ScanStateHolder.update { it.copy(running = false, awaitingHostPick = true) } // await pick
    }

    /** Single-host branch: deep-scan the chosen host in the background. */
    fun scanPickedHost(ip: String, config: ScanConfig) {
        val scanId = ScanStateHolder.current().scanId ?: return
        job?.cancel()
        job = scope.launch {
            try {
                val correlator = buildCorrelator()
                ScanStateHolder.update { it.copy(running = true, awaitingHostPick = false, hostsTotal = 1, hostsDone = 0) }
                runScan(scanId, listOf(ip), config, correlator)
            } catch (ce: CancellationException) {
                markCancelled(scanId)
                throw ce
            } catch (e: Exception) {
                markFailed(scanId, e.message ?: e.toString())
            } finally {
                onTerminal()
            }
        }
    }

    fun cancel() {
        val active = job?.isActive == true
        if (active) {
            // Cancelling triggers the CancellationException path, which marks the
            // run cancelled (see markCancelled).
            job?.cancel()
        } else {
            // No active job (e.g. sitting on the host-pick screen). Mark cancelled
            // directly so the UI can leave and the service can stop.
            scope.launch {
                val id = ScanStateHolder.current().scanId
                if (id != null) {
                    markCancelled(id)
                } else {
                    ScanStateHolder.update { it.copy(cancelled = true, running = false, finished = true) }
                }
            }
        }
    }

    // --- internals -------------------------------------------------------------

    private fun launchRun(scope0: ScanScope, config: ScanConfig, body: suspend (Long, Correlator) -> Unit) {
        job?.cancel()
        hostIds.clear()
        job = scope.launch {
            var scanId: Long? = null
            try {
                val net = networkContext.current()
                    ?: run { failNoNetwork(); return@launch }
                val cidr = net.cidr ?: run { failNoNetwork(); return@launch }
                if (cidr.prefixLength < com.watchdog.app.net.Cidr.SAFE_MIN_PREFIX && !config.allowLargeSubnet) {
                    ScanStateHolder.update {
                        it.copy(
                            failureMessage = "Subnet /${cidr.prefixLength} is too large to scan fully " +
                                "(${cidr.hostCount} hosts). Enable large-subnet scanning to proceed.",
                            finished = true, running = false,
                        )
                    }
                    return@launch
                }
                val id = repo.startScan(net, config, config.correlatorModeName())
                scanId = id
                ScanStateHolder.reset(id, scope0)
                val correlator = buildCorrelator()
                body(id, correlator)
            } catch (ce: CancellationException) {
                scanId?.let { markCancelled(it) }
                throw ce
            } catch (e: Exception) {
                scanId?.let { markFailed(it, e.message ?: e.toString()) }
                    ?: ScanStateHolder.update { it.copy(failureMessage = e.message, finished = true, running = false) }
            } finally {
                onTerminal()
            }
        }
    }

    private suspend fun ScanConfig.correlatorModeName(): String =
        settingsRepo.settings.first().correlatorMode.name

    private suspend fun discover(scanId: Long, config: ScanConfig): List<String> {
        ScanStateHolder.update { it.copy(phase = ScanPhase.DISCOVERING) }
        val net = networkContext.current()!!
        val cidr = net.cidr!!
        val ips = mutableListOf<String>()
        engine.discoverHosts(cidr, config).collect { host ->
            val hostId = repo.addHost(scanId, host)
            hostIds[host.ip] = hostId
            ips.add(host.ip)
            ScanStateHolder.update { s ->
                if (s.discoveredHosts.any { it.ip == host.ip }) s
                else s.copy(discoveredHosts = s.discoveredHosts + host)
            }
        }
        return ips
    }

    private suspend fun runScan(scanId: Long, hosts: List<String>, config: ScanConfig, correlator: Correlator) {
        engine.scan(hosts, config, correlator).collect { ev -> fold(scanId, ev) }
        repo.finishScan(scanId, "DONE")
        ScanStateHolder.update { it.copy(finished = true, running = false) }
    }

    private suspend fun fold(scanId: Long, ev: ScanEvent) {
        when (ev) {
            is ScanEvent.Phase -> ScanStateHolder.update { it.copy(phase = ev.phase) }
            is ScanEvent.HostDiscovered -> {} // handled in discover()
            is ScanEvent.HostStarted -> ScanStateHolder.update { it.copy(currentHost = ev.ip) }
            is ScanEvent.PortOpen -> ScanStateHolder.update { s ->
                val existing = s.openPortsByHost[ev.ip].orEmpty()
                s.copy(openPortsByHost = s.openPortsByHost + (ev.ip to (existing + ev.port)))
            }
            is ScanEvent.ServiceFound -> {
                hostIds[ev.observation.host]?.let { repo.addObservation(it, ev.observation) }
                ScanStateHolder.update { it.copy(services = it.services + ev.observation) }
            }
            is ScanEvent.HostFinished -> ScanStateHolder.update { it.copy(hostsDone = it.hostsDone + 1) }
            is ScanEvent.Correlated -> {
                repo.saveFindings(scanId, ev.response.findings + ev.response.suppressed)
                ScanStateHolder.update {
                    it.copy(findings = ev.response.findings, suppressed = ev.response.suppressed)
                }
            }
            is ScanEvent.Failed -> ScanStateHolder.update { it.copy(errors = it.errors + "${ev.where}: ${ev.message}") }
            ScanEvent.Done -> {}
        }
    }

    private suspend fun buildCorrelator(): Correlator {
        val s = settingsRepo.settings.first()
        return when (s.correlatorMode) {
            CorrelatorMode.OWN_SERVER ->
                if (s.serverBaseUrl.isNotBlank()) {
                    RemoteCorrelator(baseUrl = s.serverBaseUrl, token = s.serverToken.ifBlank { null })
                } else {
                    DirectOsvCorrelator() // misconfigured -> fall back
                }
            CorrelatorMode.DIRECT_OSV -> DirectOsvCorrelator()
        }
    }

    private suspend fun markCancelled(scanId: Long) {
        // Update the live state FIRST: it's non-suspending, so it always runs even
        // though we're inside a cancelled coroutine. The DB write is suspending and
        // would otherwise throw CancellationException before the UI ever hears about
        // the cancel — run it under NonCancellable so it completes too.
        ScanStateHolder.update { it.copy(cancelled = true, running = false, finished = true) }
        withContext(NonCancellable) { repo.finishScan(scanId, "CANCELLED") }
    }

    private suspend fun markFailed(scanId: Long, message: String) {
        repo.finishScan(scanId, "ERROR")
        ScanStateHolder.update { it.copy(failureMessage = message, running = false, finished = true) }
    }

    private fun failNoNetwork() {
        ScanStateHolder.update {
            it.copy(failureMessage = "No Wi-Fi network with an IPv4 subnet. Join a Wi-Fi network and retry.", finished = true, running = false)
        }
    }
}
