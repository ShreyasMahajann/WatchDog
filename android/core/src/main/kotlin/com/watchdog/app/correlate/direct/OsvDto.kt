package com.watchdog.app.correlate.direct

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Minimal OSV schema DTOs (https://ossf.github.io/osv-schema/). We deserialize
// leniently (ignoreUnknownKeys) — OSV records carry far more than we consume.

@Serializable
data class OsvQuery(
    val version: String? = null,
    @SerialName("package") val pkg: OsvPackage? = null,
)

@Serializable
data class OsvBatchRequest(val queries: List<OsvQuery>)

@Serializable
data class OsvQueryResponse(val vulns: List<OsvVuln> = emptyList())

@Serializable
data class OsvPackage(
    val name: String? = null,
    val ecosystem: String? = null,
)

@Serializable
data class OsvVuln(
    val id: String,
    val aliases: List<String> = emptyList(),
    val summary: String? = null,
    val details: String? = null,
    val affected: List<OsvAffected> = emptyList(),
    val severity: List<OsvSeverity> = emptyList(),
)

@Serializable
data class OsvAffected(
    @SerialName("package") val pkg: OsvPackage? = null,
    val ranges: List<OsvRange> = emptyList(),
    val versions: List<String> = emptyList(),
)

@Serializable
data class OsvRange(
    val type: String, // "ECOSYSTEM" | "SEMVER" | "GIT"
    val events: List<Map<String, String>> = emptyList(),
)

@Serializable
data class OsvSeverity(
    val type: String, // "CVSS_V3" | "CVSS_V4"
    val score: String, // a CVSS vector string
)
