package com.watchdog.app.data.room

import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.model.CvssVersion
import com.watchdog.app.scan.model.ExploitMaturity
import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.FindingState
import com.watchdog.app.scan.model.MatchBasis
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.scan.model.Severity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/**
 * Single source of truth for scan data. The engine writes through here as it
 * discovers, and the UI observes the same rows — so results survive process
 * death and config changes.
 */
class ScanRepository(
    private val dao: WatchDogDao,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val json = Json { encodeDefaults = true }

    suspend fun startScan(network: NetworkInfo, config: ScanConfig, correlatorMode: String): Long {
        val now = clock()
        val netId = network.cidr?.let { "${network.ssid ?: "net"}|${it.networkAddr}/${it.prefixLength}" }
            ?: "unknown-${network.localIp}"
        dao.upsertNetwork(
            NetworkEntity(
                id = netId,
                ssid = network.ssid,
                bssid = null,
                cidr = network.cidr?.let { "${com.watchdog.app.net.Cidr.longToIp(it.networkAddr)}/${it.prefixLength}" },
                gatewayIp = network.gatewayIp,
                firstSeen = now,
                lastSeen = now,
            ),
        )
        return dao.insertScan(
            ScanEntity(
                networkId = netId,
                scope = config.scope.name,
                targetHost = null,
                depth = config.depth.name,
                correlatorMode = correlatorMode,
                startedAt = now,
                finishedAt = null,
                status = "RUNNING",
            ),
        )
    }

    suspend fun findHostId(scanId: Long, ip: String): Long? = dao.findHostId(scanId, ip)

    suspend fun addHost(scanId: Long, host: DiscoveredHost): Long =
        dao.insertHost(
            HostEntity(
                scanId = scanId,
                ip = host.ip,
                hostname = host.hostname,
                discoverySources = host.source,
                osGuess = null,
                reachable = true,
            ),
        )

    /** Persist an open port + its fingerprinted service under a host row. */
    suspend fun addObservation(hostId: Long, obs: ServiceObservation) {
        val portId = dao.insertPort(
            PortEntity(hostId = hostId, port = obs.port, proto = obs.proto, state = "OPEN"),
        )
        val p = obs.product
        val serviceId = dao.insertService(
            ServiceEntity(
                portId = portId,
                serviceName = obs.serviceName,
                vendor = p?.vendor,
                product = p?.product,
                version = p?.version,
                cpe = p?.cpe,
                distro = p?.distro,
                distroRelease = p?.distroRelease,
                distroPackage = p?.distroPackage,
                distroPkgVersion = p?.distroPkgVersion,
            ),
        )
        val e = obs.evidence
        if (e != null) {
            dao.insertFingerprint(
                FingerprintEntity(
                    serviceId = serviceId,
                    banner = e.banner,
                    httpServer = e.httpServer,
                    httpPoweredBy = e.httpPoweredBy,
                    httpTitle = e.httpTitle,
                    tlsSubject = e.tlsSubject,
                    tlsIssuer = e.tlsIssuer,
                    tlsNotAfter = e.tlsNotAfter,
                    probedAt = clock(),
                ),
            )
        }
    }

    suspend fun saveFindings(scanId: Long, findings: List<Finding>) {
        dao.insertFindings(findings.map { it.toEntity(scanId) })
    }

    /** Drop every finding for a scan (used before a full re-correlation). */
    suspend fun clearFindings(scanId: Long) = dao.deleteFindings(scanId)

    /** Drop one host's findings before a per-device re-correlation. */
    suspend fun clearFindings(scanId: Long, host: String) = dao.deleteFindings(scanId, host)

    /** Replace, rather than append to, the results of a deep host re-scan. */
    suspend fun clearHostScanData(scanId: Long, host: String) {
        dao.deleteFindings(scanId, host)
        dao.deleteHostObservations(scanId, host)
    }

    suspend fun finishScan(scanId: Long, status: String) {
        dao.setScanStatus(scanId, status, clock())
    }

    fun observeScan(scanId: Long): Flow<ScanEntity?> = dao.observeScan(scanId)
    fun observeHosts(scanId: Long): Flow<List<HostEntity>> = dao.observeHosts(scanId)
    fun observeServices(scanId: Long): Flow<List<ServiceEntity>> = dao.observeServices(scanId)
    fun observeFindings(scanId: Long): Flow<List<Finding>> =
        dao.observeFindings(scanId).map { list -> list.map { it.toFinding() } }
    fun observeRecentScans(limit: Int = 25): Flow<List<ScanEntity>> = dao.observeRecentScans(limit)

    /** Rebuild the per-service observations for a scan (used for on-demand correlation). */
    fun observeObservations(scanId: Long): Flow<List<ServiceObservation>> =
        dao.observationRows(scanId).map { rows -> rows.map { rowToObservation(it) } }

    fun observeObservations(scanId: Long, host: String): Flow<List<ServiceObservation>> =
        observeObservations(scanId).map { list -> list.filter { it.host == host } }

    suspend fun renameScan(id: Long, name: String?) = dao.renameScan(id, name)

    suspend fun deleteScan(id: Long) = dao.deleteScan(id)

    // --- mapping ---------------------------------------------------------------

    private fun Finding.toEntity(scanId: Long) = FindingEntity(
        scanId = scanId,
        host = host,
        port = port,
        productJson = json.encodeToString(ProductIdentity.serializer(), product),
        cveId = cveId,
        state = state.name,
        matchBasis = matchBasis.name,
        confidence = confidence,
        severity = severity.name,
        cvssScore = cvssScore,
        cvssVersion = cvssVersion?.name,
        knownExploited = knownExploited,
        epss = epss,
        exploitMaturity = exploitMaturity.name,
        priority = priority,
        whyJson = json.encodeToString(ListSerializer(String.serializer()), why),
        remediation = remediation,
        suppressed = suppressed,
        suppressionReason = suppressionReason,
    )

    private fun FindingEntity.toFinding() = Finding(
        host = host,
        port = port,
        product = json.decodeFromString(ProductIdentity.serializer(), productJson),
        cveId = cveId,
        state = FindingState.valueOf(state),
        matchBasis = MatchBasis.valueOf(matchBasis),
        confidence = confidence,
        severity = Severity.valueOf(severity),
        cvssScore = cvssScore,
        cvssVersion = cvssVersion?.let { CvssVersion.valueOf(it) },
        knownExploited = knownExploited,
        epss = epss,
        exploitMaturity = ExploitMaturity.valueOf(exploitMaturity),
        priority = priority,
        why = json.decodeFromString(ListSerializer(String.serializer()), whyJson),
        remediation = remediation,
        suppressed = suppressed,
        suppressionReason = suppressionReason,
    )

    companion object {
        /** Flat Room row → domain observation for on-demand correlation (live or history). */
        fun rowToObservation(r: ObservationRow) = ServiceObservation(
            host = r.host,
            port = r.port,
            proto = r.proto,
            serviceName = r.serviceName,
            product = r.product?.let {
                ProductIdentity(
                    vendor = r.vendor,
                    product = it,
                    version = r.version,
                    cpe = r.cpe,
                    distro = r.distro,
                    distroRelease = r.distroRelease,
                    distroPackage = r.distroPackage,
                    distroPkgVersion = r.distroPkgVersion,
                )
            },
            evidence = ServiceEvidence(
                banner = r.banner,
                httpServer = r.httpServer,
                httpPoweredBy = r.httpPoweredBy,
                httpTitle = r.httpTitle,
                tlsSubject = r.tlsSubject,
                tlsIssuer = r.tlsIssuer,
                tlsNotAfter = r.tlsNotAfter,
            ),
            exposure = Exposure(reachable = true),
        )
    }
}
