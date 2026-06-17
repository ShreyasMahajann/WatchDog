package com.watchdog.app.correlate.engine

import com.watchdog.app.scan.model.DistroFix
import com.watchdog.app.scan.model.DistroStatus
import com.watchdog.app.scan.model.MatchBasis
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.VersionRange

// Semantics-preserving port of backend/src/match.ts. Does an observed product
// fall within a vuln's affected ranges, and does distro data override that?

// Small product-name alias map. Banners and CVE data don't always agree on the
// product token; normalize before comparing. Extend as fixtures grow.
private val PRODUCT_ALIASES: Map<String, String> = mapOf(
    "openssh_server" to "openssh",
    "openssh-server" to "openssh",
    "httpd" to "http_server", // Apache httpd == apache http_server (CPE)
    "apache" to "http_server",
    "apache2" to "http_server",
    "nginx" to "nginx",
)

fun normalizeProduct(name: String?): String {
    if (name == null) return ""
    val key = name.trim().lowercase().replace(Regex("\\s+"), "_")
    return PRODUCT_ALIASES[key] ?: key
}

fun productMatches(obs: ProductIdentity, range: VersionRange): Boolean {
    val op = normalizeProduct(obs.product)
    val rp = normalizeProduct(range.product)
    if (op == "" || rp == "") return false
    if (op != rp) return false
    // If both carry a vendor, they must agree; missing vendor on either side is
    // tolerated (banners often omit it).
    val ov = obs.vendor
    val rv = range.vendor
    if (ov != null && rv != null) {
        if (ov.trim().lowercase() != rv.trim().lowercase()) return false
    }
    return true
}

// Is `version` within this affected range? Uses the upstream comparator.
fun versionInRange(version: String, range: VersionRange): Boolean {
    val cmp = ::compareUpstream

    if (range.exactVersion != null) {
        return cmp(version, range.exactVersion) == 0
    }

    // Lower bound
    if (range.introduced != null && cmp(version, range.introduced) < 0) return false
    if (range.introducedExcluding != null && cmp(version, range.introducedExcluding) <= 0) return false

    // Upper bound
    if (range.fixed != null && cmp(version, range.fixed) >= 0) return false
    if (range.lastAffected != null && cmp(version, range.lastAffected) > 0) return false

    // With no bounds at all and no exact version, a bare product CPE means "all
    // versions affected" — treat as in-range.
    return true
}

fun classifyBasis(obs: ProductIdentity, range: VersionRange): MatchBasis {
    if (obs.version == null) return MatchBasis.PRODUCT_ONLY
    if (range.exactVersion != null) return MatchBasis.EXACT
    val hasLower = range.introduced != null || range.introducedExcluding != null
    val hasUpper = range.fixed != null || range.lastAffected != null
    if (hasLower && hasUpper) return MatchBasis.BOUNDED_RANGE
    if (hasLower || hasUpper) return MatchBasis.UPSTREAM_RANGE
    return MatchBasis.PRODUCT_ONLY
}

sealed interface DistroVerdict {
    data class Patched(val reason: String) : DistroVerdict // suppress the finding
    data class Confirmed(val reason: String) : DistroVerdict // still vulnerable -> VERIFIED
    data class NotAffected(val reason: String) : DistroVerdict // suppress
    data object None : DistroVerdict // no applicable distro data
}

// The backport ground-truth. If the observation carries a distro package
// version, distro fixed-version data OVERRIDES the upstream range verdict.
fun distroVerdict(obs: ProductIdentity, fixes: List<DistroFix>?): DistroVerdict {
    val pkgVersion = obs.distroPkgVersion
    val obsDistro = obs.distro
    if (fixes == null || obsDistro == null || pkgVersion == null) return DistroVerdict.None
    val distro = obsDistro.trim().lowercase()
    val release = obs.distroRelease?.trim()?.lowercase()

    val applicable = fixes.filter { f ->
        if (f.distro.trim().lowercase() != distro) return@filter false
        val fr = f.release
        if (release != null && fr != null && fr.trim().lowercase() != release) return@filter false
        true
    }
    if (applicable.isEmpty()) return DistroVerdict.None

    for (f in applicable) {
        when (f.status) {
            DistroStatus.NOT_AFFECTED ->
                return DistroVerdict.NotAffected("$obsDistro marks ${f.pkg} not affected")
            DistroStatus.FIXED -> {
                val fixedVersion = f.fixedVersion
                if (fixedVersion != null) {
                    val c = compareDebian(pkgVersion, fixedVersion)
                    return if (c >= 0) {
                        DistroVerdict.Patched("$obsDistro package $pkgVersion >= fixed $fixedVersion (backported)")
                    } else {
                        DistroVerdict.Confirmed("$obsDistro package $pkgVersion < fixed $fixedVersion")
                    }
                }
            }
            DistroStatus.AFFECTED ->
                return DistroVerdict.Confirmed("$obsDistro marks ${f.pkg} affected (no fix available)")
            DistroStatus.UNKNOWN -> {} // fall through
        }
    }
    return DistroVerdict.None
}
