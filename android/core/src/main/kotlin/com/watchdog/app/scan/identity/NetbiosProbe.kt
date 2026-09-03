package com.watchdog.app.scan.identity

import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation

/**
 * NetBIOS node-status query (UDP 137) — the unauthenticated way to read a
 * Windows/SMB host's computer name and workgroup. Surfaces the name in the
 * evidence banner so it's visible and searchable in results.
 */
class NetbiosProbe : IdentityProbe {

    override suspend fun probe(host: String, config: ScanConfig): ServiceObservation? {
        val txId = host.hashCode() and 0x7FFF
        val resp = UdpProbe.exchange(host, PORT, NetbiosNs.buildNodeStatusQuery(txId), config.udpProbeTimeoutMs)
            ?: return null
        val names = NetbiosNs.parseNames(resp)
        if (names.isEmpty()) return null

        val computer = NetbiosNs.hostnameOf(names)
        val workgroup = names.firstOrNull { it.group }?.name
        val banner = buildString {
            append("NetBIOS")
            computer?.let { append(" name=").append(it) }
            workgroup?.let { append(" workgroup=").append(it) }
        }
        return ServiceObservation(
            host = host,
            port = PORT,
            proto = "udp",
            serviceName = "netbios-ns",
            evidence = ServiceEvidence(banner = banner),
            exposure = Exposure(reachable = true, authless = true),
        )
    }

    private companion object {
        const val PORT = 137
    }
}
