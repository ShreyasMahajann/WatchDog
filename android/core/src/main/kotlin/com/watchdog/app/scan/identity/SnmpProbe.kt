package com.watchdog.app.scan.identity

import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation

/**
 * Asks a host for sysDescr.0 over SNMPv1 with the default "public" community — a
 * response both proves SNMP is exposed authless and hands back a descriptive OS/
 * device string (e.g. "Linux ... armv7l", a printer or router model).
 */
class SnmpProbe(private val community: String = "public") : IdentityProbe {

    override suspend fun probe(host: String, config: ScanConfig): ServiceObservation? {
        val reqId = host.hashCode() and 0x7FFF
        val resp = UdpProbe.exchange(host, PORT, SnmpV1.buildGet(community, reqId), config.udpProbeTimeoutMs)
            ?: return null
        val sysDescr = SnmpV1.parseSysDescr(resp) ?: return null
        return ServiceObservation(
            host = host,
            port = PORT,
            proto = "udp",
            serviceName = "snmp",
            evidence = ServiceEvidence(banner = sysDescr),
            exposure = Exposure(reachable = true, authless = true),
        )
    }

    private companion object {
        const val PORT = 161
    }
}
