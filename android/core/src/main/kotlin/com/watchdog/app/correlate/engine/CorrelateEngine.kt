package com.watchdog.app.correlate.engine

import com.watchdog.app.scan.model.CorrelateRequest
import com.watchdog.app.scan.model.CorrelateResponse
import com.watchdog.app.scan.model.CvssScore
import com.watchdog.app.scan.model.CvssVersion
import com.watchdog.app.scan.model.ExploitMaturity
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.FindingState
import com.watchdog.app.scan.model.MatchBasis
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.scan.model.Severity
import com.watchdog.app.scan.model.VersionRange
import com.watchdog.app.scan.model.VulnRecord

// Semantics-preserving port of backend/src/correlate.ts. Given observations and
// a VulnSource, produces ranked findings. Never performs I/O. Max state reached
// here is VERIFIED (via distro confirmation); EXPLOITABLE is set by the
// verification runtime later.

const val ENGINE_VERSION = "0.1.0"

/** Candidate vulns for a normalized product name (e.g. "openssh"). */
fun interface VulnSource {
    fun byProduct(normalizedProduct: String): List<VulnRecord>
}

object CorrelateEngine {

    fun correlate(
        req: CorrelateRequest,
        source: VulnSource,
        now: String,
    ): CorrelateResponse {
        val findings = mutableListOf<Finding>()
        val suppressed = mutableListOf<Finding>()

        for (obs in req.observations) {
            val product = obs.product ?: continue
            val np = normalizeProduct(product.product)
            if (np.isEmpty()) continue

            for (vuln in source.byProduct(np)) {
                val f = evaluate(obs, product, vuln) ?: continue
                if (f.suppressed) suppressed.add(f) else findings.add(f)
            }
        }

        findings.sortWith(::byPriority)
        suppressed.sortWith(::byPriority)
        return CorrelateResponse(findings, suppressed, now, ENGINE_VERSION)
    }

    private fun evaluate(
        obs: ServiceObservation,
        product: ProductIdentity,
        vuln: VulnRecord,
    ): Finding? {
        // Find the most specific matching range for this product.
        val candidateRanges = vuln.ranges.filter { productMatches(product, it) }
        val firstRange = candidateRanges.firstOrNull() ?: return null

        var chosen: VersionRange = firstRange
        var basis: MatchBasis = MatchBasis.PRODUCT_ONLY
        val version = product.version

        if (version != null) {
            val inRange = candidateRanges.filter { versionInRange(version, it) }
            if (inRange.isEmpty()) return null // version known and not affected
            chosen = mostSpecific(product, inRange)
            basis = classifyBasis(product, chosen)
        } else {
            // Product matches a known-vulnerable product but no readable version.
            basis = MatchBasis.PRODUCT_ONLY
        }

        val why = mutableListOf<String>()
        val verdict = distroVerdict(product, vuln.distroFixes)

        var state: FindingState
        var suppressedFlag = false
        var suppressionReason: String? = null

        if (basis == MatchBasis.PRODUCT_ONLY) {
            state = FindingState.DETECTED
            why.add("${product.product} present; version not determined")
        } else {
            state = FindingState.LIKELY_VULNERABLE
            why.add(rangeReason(product.version!!, chosen))
        }

        when (verdict) {
            is DistroVerdict.Patched -> {
                suppressedFlag = true
                suppressionReason = verdict.reason
                why.add(verdict.reason)
            }
            is DistroVerdict.NotAffected -> {
                suppressedFlag = true
                suppressionReason = verdict.reason
                why.add(verdict.reason)
            }
            is DistroVerdict.Confirmed -> {
                state = FindingState.VERIFIED
                why.add(verdict.reason)
            }
            DistroVerdict.None -> {}
        }

        val cvss = pickCvss(vuln.cvss)
        val severity: Severity = cvss?.severity ?: Severity.NONE
        val knownExploited = vuln.kev != null
        val maturity: ExploitMaturity =
            if (knownExploited) ExploitMaturity.KEV else vuln.exploitMaturity ?: ExploitMaturity.NONE
        if (knownExploited) {
            why.add(
                if (vuln.kev?.ransomware == true) {
                    "Known exploited (CISA KEV) — linked to ransomware"
                } else {
                    "Known exploited (CISA KEV)"
                },
            )
        }
        val epss = vuln.epss
        if (epss != null && epss.score >= 0.1) {
            why.add("EPSS ${(epss.score * 100).toInt()}% (exploitation likely)")
        }
        if (cvss != null) why.add("CVSS ${cvss.version.label} ${cvss.baseScore} (${cvss.severity})")

        val hasBanner = obs.evidence?.banner?.isNotEmpty() == true
        val confidence = scoreConfidence(basis, state, suppressedFlag, hasBanner)
        val priority = scorePriority(severity, maturity, vuln.epss?.score, state, basis, obs, suppressedFlag)

        return Finding(
            host = obs.host,
            port = obs.port,
            product = product,
            cveId = vuln.cveId,
            state = state,
            matchBasis = basis,
            confidence = confidence,
            severity = severity,
            cvssScore = cvss?.baseScore,
            cvssVersion = cvss?.version,
            knownExploited = knownExploited,
            epss = vuln.epss?.score,
            exploitMaturity = maturity,
            priority = priority,
            why = why,
            remediation = vuln.remediation,
            suppressed = suppressedFlag,
            suppressionReason = suppressionReason,
        )
    }

    private fun mostSpecific(product: ProductIdentity, ranges: List<VersionRange>): VersionRange {
        val order = mapOf(
            MatchBasis.EXACT to 3,
            MatchBasis.BOUNDED_RANGE to 2,
            MatchBasis.UPSTREAM_RANGE to 1,
            MatchBasis.PRODUCT_ONLY to 0,
        )
        var best = ranges[0]
        var bestScore = order.getValue(classifyBasis(product, best))
        for (r in ranges.drop(1)) {
            val s = order.getValue(classifyBasis(product, r))
            if (s > bestScore) {
                best = r
                bestScore = s
            }
        }
        return best
    }

    private fun rangeReason(version: String, r: VersionRange): String {
        if (r.exactVersion != null) {
            return "Version $version matches affected ${r.exactVersion}"
        }
        val lo = r.introduced ?: r.introducedExcluding
        val loStr = if (lo != null) ">= $lo" else "any"
        val hiStr = when {
            r.fixed != null -> "< ${r.fixed}"
            r.lastAffected != null -> "<= ${r.lastAffected}"
            else -> "up"
        }
        return "Version $version within affected range ($loStr, $hiStr)"
    }

    private val CVSS_VERSION_RANK = mapOf(
        CvssVersion.V4_0 to 4,
        CvssVersion.V3_1 to 3,
        CvssVersion.V3_0 to 2,
        CvssVersion.V2_0 to 1,
    )

    // Provenance order: prefer newer CVSS version, then CNA-provided over NVD.
    // Never average — pick one and keep it.
    private fun pickCvss(scores: List<CvssScore>?): CvssScore? {
        if (scores.isNullOrEmpty()) return null
        return scores.sortedWith(Comparator { a, b ->
            val vr = CVSS_VERSION_RANK.getValue(b.version) - CVSS_VERSION_RANK.getValue(a.version)
            if (vr != 0) return@Comparator vr
            val aCna = if (a.source.startsWith("cna")) 1 else 0
            val bCna = if (b.source.startsWith("cna")) 1 else 0
            bCna - aCna
        }).first()
    }

    private fun scoreConfidence(
        basis: MatchBasis,
        state: FindingState,
        suppressed: Boolean,
        hasBanner: Boolean,
    ): Int {
        if (state == FindingState.VERIFIED) return 95
        if (suppressed) return 20 // low confidence it's actually vulnerable
        val base = mapOf(
            MatchBasis.EXACT to 88,
            MatchBasis.BOUNDED_RANGE to 76,
            MatchBasis.UPSTREAM_RANGE to 58,
            MatchBasis.PRODUCT_ONLY to 28,
        )
        var c = base.getValue(basis)
        if (hasBanner) c = minOf(99, c + 4)
        return c
    }

    private val SEVERITY_WEIGHT = mapOf(
        Severity.CRITICAL to 1.0,
        Severity.HIGH to 0.8,
        Severity.MEDIUM to 0.55,
        Severity.LOW to 0.3,
        Severity.NONE to 0.1,
    )
    private val MATURITY_WEIGHT = mapOf(
        ExploitMaturity.KEV to 1.0,
        ExploitMaturity.WEAPONIZED to 0.8,
        ExploitMaturity.POC to 0.55,
        ExploitMaturity.NONE to 0.3,
    )
    private val STATE_WEIGHT = mapOf(
        FindingState.EXPLOITABLE to 1.0,
        FindingState.VERIFIED to 1.0,
        FindingState.LIKELY_VULNERABLE to 0.7,
        FindingState.DETECTED to 0.3,
    )
    private val BASIS_WEIGHT = mapOf(
        MatchBasis.EXACT to 1.0,
        MatchBasis.BOUNDED_RANGE to 0.9,
        MatchBasis.UPSTREAM_RANGE to 0.7,
        MatchBasis.PRODUCT_ONLY to 0.5,
    )

    private fun scorePriority(
        severity: Severity,
        maturity: ExploitMaturity,
        epss: Double?,
        state: FindingState,
        basis: MatchBasis,
        obs: ServiceObservation,
        suppressed: Boolean,
    ): Int {
        if (suppressed) return 0
        val sev = SEVERITY_WEIGHT.getValue(severity)
        val exploit = maxOf(MATURITY_WEIGHT.getValue(maturity), epss ?: 0.0)
        val stateW = STATE_WEIGHT.getValue(state)
        val basisW = BASIS_WEIGHT.getValue(basis)
        val exposureW = when {
            obs.exposure?.authless == true -> 1.0
            obs.exposure?.reachable == true -> 0.85
            else -> 0.7
        }
        val raw = sev * (0.4 + 0.6 * exploit) * stateW * basisW * exposureW
        return Math.round(raw * 100).toInt()
    }

    private fun byPriority(a: Finding, b: Finding): Int {
        if (b.priority != a.priority) return b.priority - a.priority
        val sev = SEVERITY_WEIGHT.getValue(b.severity).compareTo(SEVERITY_WEIGHT.getValue(a.severity))
        if (sev != 0) return sev
        return a.cveId.compareTo(b.cveId)
    }
}
