package com.watchdog.app.scan.model

import kotlinx.serialization.Serializable

// Kotlin mirror of backend/src/types.ts — the frozen /correlate contract.
// Field names match the TS interfaces byte-for-byte so the same JSON round-trips
// to an own-server backend, and so on-device findings equal server output.
//
// This file (and the rest of scan/model, correlate/engine) must stay free of
// android.* imports: it is covered by plain JVM unit tests.

/** What the phone extracted from a service's fingerprint. */
@Serializable
data class ProductIdentity(
    val vendor: String? = null, // e.g. "openbsd"
    val product: String, // e.g. "openssh" (normalized lowercase)
    val version: String? = null, // upstream version, e.g. "8.2p1"
    val cpe: String? = null,
    // Distro context parsed out of the banner — the backport-suppression signal.
    val distro: String? = null, // "ubuntu" | "debian" | "redhat" | ...
    val distroRelease: String? = null, // "focal" | "12" | ...
    val distroPackage: String? = null, // dpkg/rpm package name if it differs
    val distroPkgVersion: String? = null, // e.g. "1:8.2p1-4ubuntu0.11"
)

@Serializable
data class ServiceEvidence(
    val banner: String? = null,
    val httpServer: String? = null,
    val httpPoweredBy: String? = null,
    val tlsSubject: String? = null,
    val tlsIssuer: String? = null,
    val tlsNotAfter: String? = null,
)

@Serializable
data class Exposure(
    val reachable: Boolean, // the phone got a response
    val authless: Boolean? = null, // service answered without credentials
)

@Serializable
data class ServiceObservation(
    val host: String, // IP on the LAN
    val port: Int,
    val proto: String = "tcp", // "tcp" | "udp"
    val serviceName: String? = null, // "ssh", "http", ...
    val product: ProductIdentity? = null,
    val evidence: ServiceEvidence? = null,
    val exposure: Exposure? = null,
)
