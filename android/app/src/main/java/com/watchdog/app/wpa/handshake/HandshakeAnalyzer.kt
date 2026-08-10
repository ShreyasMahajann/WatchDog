package com.watchdog.app.wpa.handshake

/** A network seen in the capture, with what we found about its 4-way handshake. */
data class DetectedNetwork(
    val ssid: String?,
    val bssid: String,
    val channel: Int?,
    val security: String,
    val eapolCount: Int,
    /** Which handshake messages (1..4) were observed. */
    val messages: Set<Int>,
    val hasPmkid: Boolean,
    val hasValidHandshake: Boolean,
)

/** Result of analyzing a capture file. */
data class HandshakeAnalysis(
    val networks: List<DetectedNetwork>,
    val packetCount: Int,
    val eapolTotal: Int,
) {
    val hasValidHandshake: Boolean get() = networks.any { it.hasValidHandshake }

    /** The network best worth submitting: a valid handshake first, else the most EAPOL activity. */
    val primary: DetectedNetwork?
        get() = networks.firstOrNull { it.hasValidHandshake }
            ?: networks.maxByOrNull { it.eapolCount }
            ?: networks.firstOrNull()
}

/**
 * Turns raw capture bytes into a [HandshakeAnalysis]. Beacons/probe-responses supply SSID, channel
 * and security per BSSID; EAPOL-Key frames are grouped by AP to decide whether a crackable handshake
 * (M2 plus an ANonce from M1/M3, or a PMKID) is actually present. Nothing here is inferred — a
 * network is only "valid" if the real frames were in the file.
 */
object HandshakeAnalyzer {

    private class Agg(val bssid: String) {
        var ssid: String? = null
        var channel: Int? = null
        var security: String = "Unknown"
        var eapol = 0
        val messages = mutableSetOf<Int>()
        var pmkid = false
    }

    fun analyze(data: ByteArray): HandshakeAnalysis {
        val packets = PcapReader.read(data)
        val byBssid = LinkedHashMap<String, Agg>()
        var eapolTotal = 0

        fun agg(bssid: String) = byBssid.getOrPut(bssid) { Agg(bssid) }

        for (packet in packets) {
            when (val parsed = runCatching { Dot11Parser.parse(packet) }.getOrNull()) {
                is BeaconInfo -> {
                    val a = agg(parsed.bssid)
                    if (parsed.ssid != null) a.ssid = parsed.ssid
                    if (parsed.channel != null) a.channel = parsed.channel
                    a.security = parsed.security
                }
                is EapolInfo -> {
                    val a = agg(parsed.apMac)
                    a.eapol++
                    eapolTotal++
                    if (parsed.message in 1..4) a.messages.add(parsed.message)
                    if (parsed.hasPmkid) a.pmkid = true
                }
            }
        }

        val networks = byBssid.values.map { a ->
            val valid = a.pmkid || (a.messages.contains(2) && (a.messages.contains(1) || a.messages.contains(3)))
            DetectedNetwork(
                ssid = a.ssid,
                bssid = a.bssid,
                channel = a.channel,
                security = a.security,
                eapolCount = a.eapol,
                messages = a.messages.toSortedSet(),
                hasPmkid = a.pmkid,
                hasValidHandshake = valid,
            )
        }
        return HandshakeAnalysis(networks = networks, packetCount = packets.size, eapolTotal = eapolTotal)
    }
}
