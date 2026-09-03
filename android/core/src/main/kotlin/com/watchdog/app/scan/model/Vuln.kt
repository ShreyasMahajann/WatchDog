package com.watchdog.app.scan.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Vulnerability-intelligence records: what a VulnSource yields and the engine
// consumes. Mirrors backend/src/types.ts. @SerialName values match the TS wire
// format for own-server interop; Room mapping uses Kotlin constant names.

@Serializable
enum class Severity { NONE, LOW, MEDIUM, HIGH, CRITICAL }

@Serializable
enum class CvssVersion(val label: String) {
    @SerialName("4.0") V4_0("4.0"),
    @SerialName("3.1") V3_1("3.1"),
    @SerialName("3.0") V3_0("3.0"),
    @SerialName("2.0") V2_0("2.0"),
}

@Serializable
data class CvssScore(
    val version: CvssVersion,
    val baseScore: Double,
    val severity: Severity,
    val vector: String? = null,
    val source: String, // "cna:redhat" | "nvd" | "vulncheck" ...
)

/**
 * A single affected-version constraint for a product. Mirrors NVD CPE match
 * (versionStartIncluding / versionEndExcluding) and CNA affected[] ranges.
 */
@Serializable
data class VersionRange(
    val vendor: String? = null,
    val product: String,
    val introduced: String? = null, // inclusive lower bound
    val introducedExcluding: String? = null, // exclusive lower bound
    val fixed: String? = null, // exclusive upper bound ("fixed in")
    val lastAffected: String? = null, // inclusive upper bound
    val exactVersion: String? = null, // a single vulnerable version
    val cpe: String? = null,
)

@Serializable
enum class DistroStatus {
    @SerialName("fixed") FIXED,
    @SerialName("affected") AFFECTED,
    @SerialName("not-affected") NOT_AFFECTED,
    @SerialName("unknown") UNKNOWN,
}

@Serializable
data class DistroFix(
    val distro: String,
    val release: String? = null,
    val pkg: String,
    val status: DistroStatus,
    val fixedVersion: String? = null, // package revision that carries the fix
)

/** KEV > weaponized (metasploit/nuclei) > poc (github/edb) > none. */
@Serializable
enum class ExploitMaturity {
    @SerialName("kev") KEV,
    @SerialName("weaponized") WEAPONIZED,
    @SerialName("poc") POC,
    @SerialName("none") NONE,
}

@Serializable
data class Kev(val dateAdded: String, val ransomware: Boolean? = null)

@Serializable
data class Epss(val score: Double, val percentile: Double)

data class VulnRecord(
    val cveId: String,
    val aliases: List<String>? = null, // GHSA / DSA / USN / RHSA ...
    val ranges: List<VersionRange>,
    val distroFixes: List<DistroFix>? = null,
    val cvss: List<CvssScore>? = null, // multiple, kept with provenance; never averaged
    val kev: Kev? = null,
    val epss: Epss? = null,
    val exploitMaturity: ExploitMaturity? = null,
    val cwe: List<String>? = null,
    val summary: String? = null,
    val remediation: String? = null,
)
