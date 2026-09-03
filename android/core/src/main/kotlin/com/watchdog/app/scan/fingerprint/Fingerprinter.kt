package com.watchdog.app.scan.fingerprint

import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.enumeration.PortSets
import com.watchdog.app.scan.fingerprint.parse.HttpHeaderParser
import com.watchdog.app.scan.fingerprint.parse.SshBannerParser
import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation

/**
 * Turns an open port into a ServiceObservation by dispatching the right probe
 * (banner / HTTP / TLS) and running the pure parsers over the evidence. Every
 * probe is wrapped so a failure yields a bare observation (port only) rather
 * than aborting the host's scan.
 */
class Fingerprinter(
    private val banner: BannerGrabber = BannerGrabber(),
    private val http: HttpProber = HttpProber(),
    private val tls: TlsProber = TlsProber(),
) {
    private val tlsPorts = setOf(443, 465, 636, 993, 995, 8443, 9443, 5986, 8834, 6697)
    private val httpPorts = PortSets.WEB_LIKELY
    private val bannerPorts = setOf(21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379, 11211, 27017)

    suspend fun fingerprint(host: String, port: Int, config: ScanConfig): ServiceObservation {
        val hint = PortSets.serviceHint(port)
        var product: ProductIdentity? = null
        var evidence: ServiceEvidence? = null

        try {
            when {
                port in tlsPorts -> {
                    val info = tls.probe(host, port, config)
                    val httpRes = http.probe(host, port, tls = true)
                    product = httpRes?.server?.let { HttpHeaderParser.parseServer(it) }
                    evidence = ServiceEvidence(
                        httpServer = httpRes?.server,
                        httpPoweredBy = httpRes?.poweredBy,
                        httpTitle = httpRes?.title,
                        tlsSubject = info?.subject,
                        tlsIssuer = info?.issuer,
                        tlsNotAfter = info?.notAfter,
                    )
                }

                port in httpPorts -> {
                    val httpRes = http.probe(host, port, tls = false)
                    product = httpRes?.server?.let { HttpHeaderParser.parseServer(it) }
                    evidence = ServiceEvidence(
                        httpServer = httpRes?.server,
                        httpPoweredBy = httpRes?.poweredBy,
                        httpTitle = httpRes?.title,
                    )
                }

                port in bannerPorts || hint == "ssh" -> {
                    val raw = banner.grab(host, port, config)
                    product = SshBannerParser.parse(raw)
                    evidence = raw?.let { ServiceEvidence(banner = it) }
                }

                else -> {
                    // Unknown port: try a banner, then fall back to HTTP.
                    val raw = banner.grab(host, port, config)
                    if (raw != null) {
                        product = SshBannerParser.parse(raw)
                        evidence = ServiceEvidence(banner = raw)
                    } else {
                        val httpRes = http.probe(host, port, tls = false)
                        if (httpRes != null) {
                            product = httpRes.server?.let { HttpHeaderParser.parseServer(it) }
                            evidence = ServiceEvidence(
                                httpServer = httpRes.server,
                                httpPoweredBy = httpRes.poweredBy,
                                httpTitle = httpRes.title,
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Fall through to a bare observation.
        }

        return ServiceObservation(
            host = host,
            port = port,
            proto = "tcp",
            serviceName = product?.product ?: hint,
            product = product,
            evidence = evidence,
            exposure = Exposure(reachable = true, authless = true),
        )
    }
}
