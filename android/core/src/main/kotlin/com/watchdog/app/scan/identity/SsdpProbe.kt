package com.watchdog.app.scan.identity

import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.fingerprint.parse.HttpHeaderParser
import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation

/**
 * Unicast SSDP M-SEARCH (UDP 1900) — many UPnP devices (media servers, routers,
 * smart-home hubs, cameras) answer directly with a SERVER string that names the
 * OS/stack, which we parse into a product for correlation and show as evidence.
 */
class SsdpProbe : IdentityProbe {

    override suspend fun probe(host: String, config: ScanConfig): ServiceObservation? {
        val resp = UdpProbe.exchange(host, PORT, Ssdp.buildMSearch(host, PORT), config.udpProbeTimeoutMs)
            ?: return null
        val info = Ssdp.parseResponse(String(resp, Charsets.ISO_8859_1)) ?: return null
        val product = info.server?.let { HttpHeaderParser.parseServer(it) }
        return ServiceObservation(
            host = host,
            port = PORT,
            proto = "udp",
            serviceName = product?.product ?: "upnp",
            product = product,
            evidence = ServiceEvidence(banner = info.server, httpTitle = info.location),
            exposure = Exposure(reachable = true, authless = true),
        )
    }

    private companion object {
        const val PORT = 1900
    }
}
