package com.watchdog.app.correlate.direct

import com.watchdog.app.correlate.Correlator
import com.watchdog.app.correlate.engine.CorrelateEngine
import com.watchdog.app.correlate.engine.VulnSource
import com.watchdog.app.correlate.engine.normalizeProduct
import com.watchdog.app.scan.model.CorrelateRequest
import com.watchdog.app.scan.model.CorrelateResponse
import com.watchdog.app.scan.model.CvssScore
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.scan.model.VersionRange
import com.watchdog.app.scan.model.VulnRecord

/**
 * Backend-less correlation. For each observed product it asks OSV.dev which
 * vulns affect that exact version, then threads the answers through the ported
 * CorrelateEngine so scoring/prioritization/dedup match the server contract.
 *
 * Two accuracy tiers (see plan):
 *  - Distro-tagged services get an ecosystem query with the package revision.
 *    OSV's distro data is backport-aware, so a returned vuln is genuinely
 *    applicable — surfaced as an exact-match LIKELY_VULNERABLE.
 *  - Bare upstream products (no distro/ecosystem) have no reliable OSV version
 *    filter, so their vulns are surfaced as low-confidence DETECTED, never
 *    asserted vulnerable. This is exactly the gap own-server mode closes.
 *
 * KEV and EPSS are overlaid onto every candidate for prioritization.
 */
class DirectOsvCorrelator(
    private val osv: OsvClient = OsvClient(),
    private val kev: KevClient = KevClient(),
    private val epss: EpssClient = EpssClient(),
    private val now: () -> String = { java.time.Instant.now().toString() },
) : Correlator {

    private companion object {
        // Cap versionless OSV results per product so a broad package (e.g. a busy
        // web server) can't flood the KEV filter with a huge candidate list.
        const val MAX_VERSIONLESS_VULNS = 200
    }

    override suspend fun correlate(observations: List<ServiceObservation>): CorrelateResponse {
        // Group synthesized vuln records by normalized product for the VulnSource.
        val byProduct = mutableMapOf<String, MutableList<VulnRecord>>()

        // De-duplicate identical queries across hosts running the same service.
        val queried = mutableSetOf<String>()

        // Products seen without a readable version: we can't assert vulnerability,
        // but we query OSV by name and (below) keep only the actively-exploited
        // (KEV-listed) hits — high signal without the version-confirmation noise.
        val versionlessCandidates = mutableMapOf<String, MutableList<OsvVuln>>()

        for (obs in observations) {
            val product = obs.product ?: continue
            val np = normalizeProduct(product.product)
            if (np.isEmpty()) continue
            val obsVersion = product.version

            if (obsVersion == null) {
                if (!queried.add("versionless|$np")) continue
                val vulns = osv.query(OsvPackage(name = np), version = null)
                if (vulns.isNotEmpty()) {
                    versionlessCandidates.getOrPut(np) { mutableListOf() }
                        .addAll(vulns.take(MAX_VERSIONLESS_VULNS))
                }
                continue
            }

            val eco = ecosystemFor(product)
            val queryKey = "${eco?.ecosystem}|${eco?.name}|$obsVersion|$np"
            if (!queried.add(queryKey)) continue

            val ecosystemConfident = eco != null
            val pkg = eco ?: OsvPackage(name = np)
            val version = if (ecosystemConfident) product.distroPkgVersion ?: obsVersion else obsVersion

            val vulns = osv.query(pkg, version)
            for (v in vulns) {
                val record = toVulnRecord(v, np, obsVersion, ecosystemConfident) ?: continue
                byProduct.getOrPut(np) { mutableListOf() }.add(record)
            }
        }

        // Overlay KEV + EPSS across every collected CVE ID (versioned records plus
        // the versionless candidates we still need KEV to filter).
        val versionedIds = byProduct.values.flatten().map { it.cveId }.toSet()
        val versionlessIds = versionlessCandidates.values.flatten().mapNotNull { cveIdOf(it) }.toSet()
        val cveIds = versionedIds + versionlessIds
        val kevMap = if (cveIds.isEmpty()) emptyMap() else kev.fetch()
        val epssMap = if (cveIds.isEmpty()) emptyMap() else epss.fetch(cveIds)

        // Promote only KEV-listed versionless candidates to product-only records.
        for ((np, vulns) in versionlessCandidates) {
            for (v in vulns) {
                val cveId = cveIdOf(v) ?: continue
                if (kevMap[cveId] == null) continue
                val record = toVulnRecord(v, np, observedVersion = null, ecosystemConfident = false) ?: continue
                byProduct.getOrPut(np) { mutableListOf() }.add(record)
            }
        }

        val enriched = byProduct.mapValues { (_, records) ->
            records.map { r ->
                r.copy(
                    kev = kevMap[r.cveId] ?: r.kev,
                    epss = epssMap[r.cveId] ?: r.epss,
                )
            }
        }

        val source = VulnSource { np -> enriched[np] ?: emptyList() }
        return CorrelateEngine.correlate(CorrelateRequest(observations), source, now())
    }

    /** Maps distro context to an OSV ecosystem query, or null if we can't. */
    private fun ecosystemFor(p: ProductIdentity): OsvPackage? {
        val distro = p.distro?.lowercase() ?: return null
        val name = p.distroPackage ?: normalizeProduct(p.product)
        val ecosystem = when (distro) {
            "debian" -> p.distroRelease?.let { "Debian:$it" }
            "alpine" -> p.distroRelease?.let { "Alpine:v$it" }
            else -> null // Ubuntu/RHEL need a release we can't reliably read from banners yet
        } ?: return null
        return OsvPackage(name = name, ecosystem = ecosystem)
    }

    private fun cveIdOf(v: OsvVuln): String? =
        v.aliases.firstOrNull { it.startsWith("CVE-") } ?: v.id.takeIf { it.startsWith("CVE-") }

    private fun toVulnRecord(
        v: OsvVuln,
        normalizedProduct: String,
        observedVersion: String?,
        ecosystemConfident: Boolean,
    ): VulnRecord? {
        val cveId = v.aliases.firstOrNull { it.startsWith("CVE-") } ?: v.id
        // Ecosystem-confident with a version: OSV already confirmed this version is
        // affected, so carry the CVE with a self-matching exact range. Otherwise
        // (upstream, or versionless) leave the range bare so the engine emits a
        // low-confidence DETECTED.
        val range = if (ecosystemConfident && observedVersion != null) {
            VersionRange(product = normalizedProduct, exactVersion = observedVersion)
        } else {
            VersionRange(product = normalizedProduct)
        }
        val cvss = bestCvss(v)
        return VulnRecord(
            cveId = cveId,
            aliases = v.aliases.ifEmpty { null },
            ranges = listOf(range),
            cvss = cvss?.let { listOf(it) },
            summary = v.summary ?: v.details?.take(400),
        )
    }

    private fun bestCvss(v: OsvVuln): CvssScore? =
        v.severity
            .mapNotNull { s -> CvssV3.fromVector(s.score, source = "osv") }
            .maxByOrNull { it.baseScore }
}
