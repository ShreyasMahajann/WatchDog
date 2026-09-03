package com.watchdog.app.wpa.handshake

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import java.io.ByteArrayOutputStream
import org.junit.Test

/**
 * Exercises the parser against hand-assembled but spec-correct pcap bytes: a WPA2 beacon plus real
 * EAPOL-Key frames. The fixtures are genuine 802.11 frames, so a pass means the parser reads real
 * captures — not that the app pretends to.
 */
class HandshakeAnalyzerTest {

    private val bssid = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte())
    private val sta = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
    private val bcast = ByteArray(6) { 0xFF.toByte() }

    // --- byte helpers ---------------------------------------------------------

    private fun ByteArrayOutputStream.u8(v: Int) = write(v and 0xFF)
    private fun ByteArrayOutputStream.u16le(v: Int) { write(v and 0xFF); write((v shr 8) and 0xFF) }
    private fun ByteArrayOutputStream.u16be(v: Int) { write((v shr 8) and 0xFF); write(v and 0xFF) }
    private fun ByteArrayOutputStream.u32le(v: Long) {
        write((v and 0xFF).toInt()); write(((v shr 8) and 0xFF).toInt())
        write(((v shr 16) and 0xFF).toInt()); write(((v shr 24) and 0xFF).toInt())
    }
    private fun ByteArrayOutputStream.zeros(n: Int) = repeat(n) { write(0) }
    private fun ByteArrayOutputStream.b(a: ByteArray) = write(a)

    /** Wrap raw 802.11 frames in a classic little-endian pcap with DLT 105 (raw 802.11). */
    private fun pcap(frames: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.b(byteArrayOf(0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte())) // magic LE µs
        out.u16le(2); out.u16le(4)   // version
        out.u32le(0); out.u32le(0)   // thiszone, sigfigs
        out.u32le(65535)             // snaplen
        out.u32le(105)               // network = DLT_IEEE802_11
        frames.forEach { f ->
            out.u32le(0); out.u32le(0)          // ts sec/usec
            out.u32le(f.size.toLong()); out.u32le(f.size.toLong())
            out.b(f)
        }
        return out.toByteArray()
    }

    private fun beacon(): ByteArray {
        val o = ByteArrayOutputStream()
        o.u8(0x80); o.u8(0x00)          // FC: mgmt/beacon
        o.u16le(0)                       // duration
        o.b(bcast); o.b(bssid); o.b(bssid) // addr1/2/3
        o.u16le(0)                       // seq
        o.zeros(8); o.u16le(0x0064)      // timestamp, beacon interval
        o.u16le(0x0011)                  // capability: ESS + Privacy
        // SSID IE
        o.u8(0); o.u8(8); o.b("TestNet1".toByteArray())
        // DS param (channel 6)
        o.u8(3); o.u8(1); o.u8(6)
        // RSN IE (tag 48) with PSK AKM -> WPA2
        o.u8(48); o.u8(20)
        o.u16le(1)                       // version
        o.b(byteArrayOf(0x00, 0x0F, 0xAC.toByte(), 0x04)) // group CCMP
        o.u16le(1); o.b(byteArrayOf(0x00, 0x0F, 0xAC.toByte(), 0x04)) // pairwise CCMP
        o.u16le(1); o.b(byteArrayOf(0x00, 0x0F, 0xAC.toByte(), 0x02)) // akm PSK
        o.u16le(0)                       // RSN capabilities
        return o.toByteArray()
    }

    private fun dataHeader(o: ByteArrayOutputStream, fromAp: Boolean) {
        o.u8(0x08)                       // FC: data, subtype 0
        o.u8(if (fromAp) 0x02 else 0x01) // fromDS (AP->STA) or toDS (STA->AP)
        o.u16le(0)                       // duration
        if (fromAp) { o.b(sta); o.b(bssid); o.b(bssid) } else { o.b(bssid); o.b(sta); o.b(bssid) }
        o.u16le(0)                       // seq
        o.b(byteArrayOf(0xAA.toByte(), 0xAA.toByte(), 0x03, 0x00, 0x00, 0x00)) // LLC/SNAP
        o.u16be(0x888E)                  // EtherType EAPOL
    }

    /** Build an EAPOL-Key frame. [keyInfo] sets the message role; [keyData] optional RSN/PMKID bytes. */
    private fun eapol(fromAp: Boolean, keyInfo: Int, keyData: ByteArray = ByteArray(0)): ByteArray {
        val o = ByteArrayOutputStream()
        dataHeader(o, fromAp)
        val bodyLen = 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 + 2 + keyData.size
        o.u8(0x02); o.u8(0x03); o.u16be(bodyLen) // 802.1X: version 2, EAPOL-Key, length
        o.u8(0x02)                       // descriptor type RSN
        o.u16be(keyInfo)
        o.u16be(0x10)                    // key length
        o.zeros(8)                       // replay counter
        repeat(32) { o.u8(0x42) }        // nonce (non-zero)
        o.zeros(16)                      // key IV
        o.zeros(8)                       // key RSC
        o.zeros(8)                       // key ID
        if (keyInfo and 0x0100 != 0) repeat(16) { o.u8(0x7A) } else o.zeros(16) // MIC
        o.u16be(keyData.size)
        o.b(keyData)
        return o.toByteArray()
    }

    private val KEYINFO_M1 = 0x008A // pairwise + ACK
    private val KEYINFO_M2 = 0x010A // pairwise + MIC
    private val rsnKeyData = byteArrayOf(
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC.toByte(), 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC.toByte(), 0x04, 0x01, 0x00,
        0x00, 0x0F, 0xAC.toByte(), 0x02, 0x00, 0x00,
    )
    private val pmkidKeyData = byteArrayOf(
        0xDD.toByte(), 0x14, 0x00, 0x0F, 0xAC.toByte(), 0x04, // PMKID KDE header
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // 16-byte PMKID
    )

    @Test
    fun `beacon supplies ssid channel and WPA2 security`() {
        val a = HandshakeAnalyzer.analyze(pcap(listOf(beacon())))
        val net = a.networks.single()
        assertEquals("TestNet1", net.ssid)
        assertEquals("aa:bb:cc:dd:ee:ff", net.bssid)
        assertEquals(6, net.channel)
        assertEquals("WPA2", net.security)
        assertFalse(net.hasValidHandshake)
    }

    @Test
    fun `M1 plus M2 is a valid handshake`() {
        val a = HandshakeAnalyzer.analyze(
            pcap(listOf(beacon(), eapol(fromAp = true, keyInfo = KEYINFO_M1), eapol(fromAp = false, keyInfo = KEYINFO_M2, keyData = rsnKeyData))),
        )
        val net = a.primary
        assertNotNull(net)
        assertEquals("TestNet1", net!!.ssid)
        assertEquals(setOf(1, 2), net.messages)
        assertEquals(2, net.eapolCount)
        assertTrue(net.hasValidHandshake)
        assertTrue(a.hasValidHandshake)
    }

    @Test
    fun `PMKID in M1 alone is a valid handshake`() {
        val a = HandshakeAnalyzer.analyze(
            pcap(listOf(beacon(), eapol(fromAp = true, keyInfo = KEYINFO_M1, keyData = pmkidKeyData))),
        )
        val net = a.networks.single()
        assertTrue(net.hasPmkid)
        assertTrue(net.hasValidHandshake)
    }

    @Test
    fun `beacon only is not a valid handshake`() {
        val a = HandshakeAnalyzer.analyze(pcap(listOf(beacon())))
        assertFalse(a.hasValidHandshake)
        assertEquals(0, a.eapolTotal)
    }

    @Test
    fun `non-pcap bytes are rejected`() {
        try {
            HandshakeAnalyzer.analyze(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25))
            throw AssertionError("expected NotAPcapException")
        } catch (e: NotAPcapException) {
            // expected
        }
    }
}
