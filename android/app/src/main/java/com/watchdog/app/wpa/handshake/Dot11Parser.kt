package com.watchdog.app.wpa.handshake

/** Link-layer types we understand (from tcpdump/libpcap DLT registry). */
private const val DLT_IEEE802_11 = 105
private const val DLT_PRISM = 119
private const val DLT_IEEE802_11_RADIOTAP = 127
private const val DLT_PPI = 192

/** A beacon or probe-response we parsed network facts out of. */
internal data class BeaconInfo(
    val bssid: String,
    val ssid: String?,
    val channel: Int?,
    val security: String,
)

/** One EAPOL-Key frame located and classified within the 4-way handshake. */
internal data class EapolInfo(
    val apMac: String,
    val staMac: String,
    /** 1..4 for the handshake message, or 0 if it's EAPOL-Key but not classifiable. */
    val message: Int,
    val hasPmkid: Boolean,
)

/** Parses a single captured frame. Returns a [BeaconInfo], an [EapolInfo], or null if neither. */
internal object Dot11Parser {

    fun parse(packet: RawPacket): Any? {
        val mpdu = stripToMpdu(packet) ?: return null
        if (mpdu.size < 24) return null
        return parseMpdu(mpdu)
    }

    /** Remove any radiotap/PPI/prism header so we're left with the raw 802.11 MPDU. */
    private fun stripToMpdu(packet: RawPacket): ByteArray? = when (packet.linkType) {
        DLT_IEEE802_11 -> packet.payload
        DLT_IEEE802_11_RADIOTAP -> {
            val p = packet.payload
            if (p.size < 4) null else {
                val len = ((p[2].toInt() and 0xFF)) or ((p[3].toInt() and 0xFF) shl 8) // radiotap len, LE
                if (len in 0..p.size) p.copyOfRange(len, p.size) else null
            }
        }
        DLT_PPI -> {
            val p = packet.payload
            if (p.size < 4) null else {
                val len = ((p[2].toInt() and 0xFF)) or ((p[3].toInt() and 0xFF) shl 8) // PPI len, LE
                if (len in 0..p.size) p.copyOfRange(len, p.size) else null
            }
        }
        DLT_PRISM -> {
            val p = packet.payload
            if (p.size > 144) p.copyOfRange(144, p.size) else null // prism header is a fixed 144 bytes
        }
        else -> null
    }

    private fun parseMpdu(mpdu: ByteArray): Any? {
        val fc0 = mpdu[0].toInt() and 0xFF
        val fc1 = mpdu[1].toInt() and 0xFF
        val type = (fc0 shr 2) and 0x3
        val subtype = (fc0 shr 4) and 0xF
        val toDs = (fc1 and 0x01) != 0
        val fromDs = (fc1 and 0x02) != 0

        val addr1 = mpdu.copyOfRange(4, 10)
        val addr2 = mpdu.copyOfRange(10, 16)
        val addr3 = mpdu.copyOfRange(16, 22)

        return when (type) {
            0 -> if (subtype == 8 || subtype == 5) parseBeacon(mpdu, bssid = addr3.macString()) else null // beacon/probe-resp
            2 -> parseData(mpdu, subtype, toDs, fromDs, addr1, addr2, addr3)
            else -> null
        }
    }

    private fun parseBeacon(mpdu: ByteArray, bssid: String): BeaconInfo? {
        // 24-byte MAC header, then 12 bytes fixed (timestamp, interval, capability), then tagged IEs.
        var pos = 24
        if (mpdu.size < pos + 12) return null
        val capInfo = (mpdu[pos + 10].toInt() and 0xFF) or ((mpdu[pos + 11].toInt() and 0xFF) shl 8)
        pos += 12

        var ssid: String? = null
        var channel: Int? = null
        var hasRsn = false
        var hasWpa = false
        var rsnAkmSae = false

        while (pos + 2 <= mpdu.size) {
            val tag = mpdu[pos].toInt() and 0xFF
            val len = mpdu[pos + 1].toInt() and 0xFF
            val valStart = pos + 2
            if (valStart + len > mpdu.size) break
            when (tag) {
                0 -> ssid = String(mpdu, valStart, len, Charsets.UTF_8).takeIf { len > 0 }
                3 -> if (len >= 1) channel = mpdu[valStart].toInt() and 0xFF
                48 -> { hasRsn = true; rsnAkmSae = rsnHasSae(mpdu, valStart, len) }
                221 -> if (len >= 4 && isMsWpaOui(mpdu, valStart)) hasWpa = true
            }
            pos = valStart + len
        }

        val privacy = (capInfo and 0x0010) != 0
        val security = when {
            hasRsn && rsnAkmSae -> "WPA3"
            hasRsn -> "WPA2"
            hasWpa -> "WPA"
            privacy -> "WEP"
            else -> "Open"
        }
        return BeaconInfo(bssid = bssid, ssid = ssid, channel = channel, security = security)
    }

    /** RSN element (tag 48) AKM suite 00-0F-AC-08 = SAE (WPA3). */
    private fun rsnHasSae(mpdu: ByteArray, start: Int, len: Int): Boolean {
        // version(2) + group cipher(4) + pairwise count(2)+list + akm count(2)+list. Scan for 00 0F AC 08.
        val end = start + len
        var i = start
        while (i + 4 <= end) {
            if ((mpdu[i].toInt() and 0xFF) == 0x00 && (mpdu[i + 1].toInt() and 0xFF) == 0x0F &&
                (mpdu[i + 2].toInt() and 0xFF) == 0xAC && (mpdu[i + 3].toInt() and 0xFF) == 0x08
            ) return true
            i++
        }
        return false
    }

    private fun isMsWpaOui(mpdu: ByteArray, start: Int): Boolean =
        (mpdu[start].toInt() and 0xFF) == 0x00 && (mpdu[start + 1].toInt() and 0xFF) == 0x50 &&
            (mpdu[start + 2].toInt() and 0xFF) == 0xF2 && (mpdu[start + 3].toInt() and 0xFF) == 0x01

    private fun parseData(
        mpdu: ByteArray,
        subtype: Int,
        toDs: Boolean,
        fromDs: Boolean,
        addr1: ByteArray,
        addr2: ByteArray,
        addr3: ByteArray,
    ): EapolInfo? {
        // Resolve AP vs station from the DS bits.
        val (apMac, staMac) = when {
            toDs && !fromDs -> addr1 to addr2   // STA -> AP
            !toDs && fromDs -> addr2 to addr1   // AP -> STA
            else -> return null                 // ad-hoc / WDS: not an infra handshake
        }

        var headerLen = if (toDs && fromDs) 30 else 24
        if ((subtype and 0x08) != 0) headerLen += 2 // QoS data carries a 2-byte QoS control field
        if (mpdu.size < headerLen + 8) return null

        // LLC/SNAP: AA AA 03 00 00 00, then EtherType. EAPOL = 0x888E.
        val s = headerLen
        val snapOk = (mpdu[s].toInt() and 0xFF) == 0xAA && (mpdu[s + 1].toInt() and 0xFF) == 0xAA &&
            (mpdu[s + 2].toInt() and 0xFF) == 0x03
        if (!snapOk) return null
        val ether = ((mpdu[s + 6].toInt() and 0xFF) shl 8) or (mpdu[s + 7].toInt() and 0xFF)
        if (ether != 0x888E) return null

        return parseEapol(mpdu, s + 8, apMac.macString(), staMac.macString())
    }

    private fun parseEapol(mpdu: ByteArray, start: Int, apMac: String, staMac: String): EapolInfo? {
        // 802.1X header: version(1), type(1), length(2). type 3 = EAPOL-Key.
        if (start + 4 > mpdu.size) return null
        val x1Type = mpdu[start + 1].toInt() and 0xFF
        if (x1Type != 3) return null

        val body = start + 4
        // EAPOL-Key: descType(1) keyInfo(2) keyLen(2) replay(8) nonce(32) iv(16) rsc(8) id(8) mic(16) keyDataLen(2) keyData
        if (body + 1 + 2 > mpdu.size) return null
        val keyInfo = ((mpdu[body + 1].toInt() and 0xFF) shl 8) or (mpdu[body + 2].toInt() and 0xFF)

        val mic = (keyInfo and 0x0100) != 0
        val ack = (keyInfo and 0x0080) != 0
        val install = (keyInfo and 0x0040) != 0

        val keyDataLenOff = body + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16
        var hasPmkid = false
        var keyDataLen = 0
        if (keyDataLenOff + 2 <= mpdu.size) {
            keyDataLen = ((mpdu[keyDataLenOff].toInt() and 0xFF) shl 8) or (mpdu[keyDataLenOff + 1].toInt() and 0xFF)
            val kdStart = keyDataLenOff + 2
            if (keyDataLen in 1..(mpdu.size - kdStart)) {
                hasPmkid = scanForPmkid(mpdu, kdStart, keyDataLen)
            }
        }

        val message = when {
            !mic && ack -> 1                       // M1: AP, ANonce, no MIC
            mic && ack && install -> 3             // M3: AP, MIC+ACK+Install
            mic && !ack && keyDataLen > 0 -> 2     // M2: STA, MIC, carries RSN
            mic && !ack -> 4                        // M4: STA, MIC, empty key data
            else -> 0
        }
        return EapolInfo(apMac = apMac, staMac = staMac, message = message, hasPmkid = hasPmkid)
    }

    /** RSN PMKID KDE inside key data: DD <len> 00 0F AC 04 <16-byte PMKID>. */
    private fun scanForPmkid(mpdu: ByteArray, start: Int, len: Int): Boolean {
        val end = (start + len).coerceAtMost(mpdu.size)
        var i = start
        while (i + 6 <= end) {
            if ((mpdu[i].toInt() and 0xFF) == 0xDD &&
                (mpdu[i + 2].toInt() and 0xFF) == 0x00 && (mpdu[i + 3].toInt() and 0xFF) == 0x0F &&
                (mpdu[i + 4].toInt() and 0xFF) == 0xAC && (mpdu[i + 5].toInt() and 0xFF) == 0x04
            ) return true
            i++
        }
        return false
    }
}
