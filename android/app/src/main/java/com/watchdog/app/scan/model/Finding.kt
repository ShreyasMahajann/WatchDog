package com.watchdog.app.scan.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Engine output. Mirrors backend/src/types.ts Finding / CorrelateRequest /
// CorrelateResponse. @SerialName values match the TypeScript wire format so
// own-server responses decode. Room mapping uses the Kotlin constant name and
// is unaffected.

/**
 * The four states from the plan. The pure correlation engine reaches up to
 * VERIFIED (via distro confirmation); EXPLOITABLE is set later by the on-device
 * verification runtime.
 */
@Serializable
enum class FindingState {
    DETECTED, // product identified, version unknown/unassessable
    LIKELY_VULNERABLE, // version-in-range match, unconfirmed
    VERIFIED, // distro-confirmed (or active-check-confirmed elsewhere)
    EXPLOITABLE, // verified + successful authorized PoC (set by verifier)
}

/** How specific the version match was — drives confidence. */
@Serializable
enum class MatchBasis {
    @SerialName("exact") EXACT,
    @SerialName("bounded-range") BOUNDED_RANGE,
    @SerialName("upstream-range") UPSTREAM_RANGE,
    @SerialName("product-only") PRODUCT_ONLY,
}

@Serializable
data class Finding(
    val host: String,
    val port: Int,
    val product: ProductIdentity,
    val cveId: String,
    val state: FindingState,
    val matchBasis: MatchBasis,
    val confidence: Int, // 0-100
    val severity: Severity,
    val cvssScore: Double? = null,
    val cvssVersion: CvssVersion? = null,
    val knownExploited: Boolean,
    val epss: Double? = null,
    val exploitMaturity: ExploitMaturity,
    val priority: Int, // 0-100 ranking score
    val why: List<String>, // human-readable reasons
    val remediation: String? = null,
    val suppressed: Boolean, // distro says this package revision is patched
    val suppressionReason: String? = null,
)

@Serializable
data class CorrelateRequest(
    val observations: List<ServiceObservation>,
)

@Serializable
data class CorrelateResponse(
    val findings: List<Finding>,
    val suppressed: List<Finding>, // patched-by-distro, surfaced separately
    val generatedAt: String,
    val engineVersion: String,
)
