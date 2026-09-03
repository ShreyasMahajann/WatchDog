package com.watchdog.desktop

import com.watchdog.app.correlate.direct.DirectOsvCorrelator
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.scan.ScanEvent
import com.watchdog.app.scan.ScanScope
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.discovery.ReachabilityDiscoverer
import com.watchdog.app.scan.discovery.TcpProbeDiscoverer
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.desktop.net.DesktopNetworkContext
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking

/**
 * Proves the shared :core engine runs unchanged on desktop (Windows/Linux): it
 * detects the current LAN via [DesktopNetworkContext], discovers live hosts,
 * enumerates + fingerprints them with the same [ScanEngine] the Android app uses,
 * and (optionally) correlates on-device via OSV. Run:
 *
 *   gradle :desktop:run                 # discover + scan the local subnet
 *   gradle :desktop:run --args="--correlate"   # also run CVE correlation
 */
fun main(args: Array<String>) = runBlocking {
    val correlate = args.contains("--correlate")
    val netCtx = DesktopNetworkContext()
    val net = netCtx.current()
    if (net?.cidr == null) {
        System.err.println("No active IPv4 LAN found. Connect to a network and retry.")
        return@runBlocking
    }
    println("watchDog desktop headless scan")
    println("Interface: local=${net.localIp} gateway=${net.gatewayIp ?: "?"} wifi=${net.isWifi}")
    println("Subnet: ${net.cidr!!.let { com.watchdog.app.net.Cidr.longToIp(it.networkAddr) }}/${net.cidr!!.prefixLength} (${net.cidr!!.hostCount} hosts)")

    val engine = ScanEngine(
        discoverers = listOf(TcpProbeDiscoverer(), ReachabilityDiscoverer()),
    )
    val config = ScanConfig(scope = ScanScope.WHOLE_NETWORK, depth = ScanDepth.TOP_100, identityProbes = false)

    print("Discovering hosts… ")
    val hosts = engine.discoverHosts(net.cidr!!, config).toList().map { it.ip }
    println("found ${hosts.size}: $hosts")
    if (hosts.isEmpty()) return@runBlocking

    val observations = mutableListOf<ServiceObservation>()
    engine.scan(hosts, config).collect { ev ->
        when (ev) {
            is ScanEvent.HostStarted -> println("  scanning ${ev.ip}")
            is ScanEvent.PortOpen -> println("    open ${ev.ip}:${ev.port} ${ev.serviceHint ?: ""}")
            is ScanEvent.ServiceFound -> {
                observations += ev.observation
                val p = ev.observation.product
                println("    service ${ev.observation.host}:${ev.observation.port} " +
                    "${ev.observation.serviceName ?: ""} ${p?.product ?: ""} ${p?.version ?: ""}".trimEnd())
            }
            is ScanEvent.Failed -> System.err.println("    ! ${ev.where}: ${ev.message}")
            else -> {}
        }
    }
    println("Enumerated ${observations.size} service(s) across ${hosts.size} host(s).")

    if (correlate && observations.isNotEmpty()) {
        println("Correlating against OSV/KEV/EPSS…")
        val response = DirectOsvCorrelator().correlate(observations)
        println("Findings: ${response.findings.size} (suppressed ${response.suppressed.size})")
        response.findings.sortedByDescending { it.priority }.take(20).forEach { f ->
            println("  [${f.severity}] ${f.cveId} ${f.product.product} ${f.host}:${f.port} " +
                "prio=${f.priority} ${f.state}")
        }
    }
}
