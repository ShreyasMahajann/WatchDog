package com.watchdog.app.scan.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityCodecTest {

    // --- SNMP ------------------------------------------------------------------

    @Test
    fun snmp_buildGet_isBerSequenceCarryingCommunityAndOid() {
        val req = SnmpV1.buildGet(community = "public", requestId = 1)
        assertEquals(0x30, req[0].toInt() and 0xFF) // outer SEQUENCE
        assertTrue(indexOf(req, "public".toByteArray()) >= 0)
        // sysDescr.0 OID bytes: 2B 06 01 02 01 01 01 00
        val oidBytes = byteArrayOf(0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00)
        assertTrue(indexOf(req, oidBytes) >= 0)
    }

    @Test
    fun snmp_parseSysDescr_extractsTheStringValue() {
        // A hand-built GetResponse for sysDescr.0 == "Test Router".
        val value = "Test Router".toByteArray(Charsets.US_ASCII)
        val oid = byteArrayOf(0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00)
        val valTlv = byteArrayOf(0x04, value.size.toByte()) + value
        val varbind = tlv(0x30, oid + valTlv)
        val varbindList = tlv(0x30, varbind)
        val pdu = tlv(0xA2, bytes(0x02, 0x01, 0x01) + bytes(0x02, 0x01, 0x00) + bytes(0x02, 0x01, 0x00) + varbindList)
        val community = tlv(0x04, "public".toByteArray())
        val resp = tlv(0x30, bytes(0x02, 0x01, 0x00) + community + pdu)

        assertEquals("Test Router", SnmpV1.parseSysDescr(resp))
    }

    @Test
    fun snmp_parseSysDescr_returnsNullOnGarbage() {
        assertNull(SnmpV1.parseSysDescr(byteArrayOf(0x01, 0x02, 0x03)))
    }

    // --- NetBIOS ---------------------------------------------------------------

    @Test
    fun netbios_query_encodesWildcardNameAndNbstatType() {
        val q = NetbiosNs.buildNodeStatusQuery(0x1234)
        assertEquals(0x12, q[0].toInt() and 0xFF)
        assertEquals(0x34, q[1].toInt() and 0xFF)
        // wildcard "*" first-level encodes to "CK" followed by "AA" pairs.
        val encoded = String(q.copyOfRange(13, 13 + 32), Charsets.US_ASCII)
        assertTrue(encoded.startsWith("CK"))
        // QTYPE NBSTAT (0x0021) sits right after the 0x00 name terminator.
        assertEquals(0x21, q[q.size - 3].toInt() and 0xFF)
    }

    @Test
    fun netbios_parseNames_readsComputerNameFromNodeStatus() {
        val resp = buildNbstatResponse(listOf("MYPC" to 0x00, "WORKGROUP" to 0x00))
        val names = NetbiosNs.parseNames(resp)
        assertEquals("MYPC", NetbiosNs.hostnameOf(names))
    }

    // --- SSDP ------------------------------------------------------------------

    @Test
    fun ssdp_parseResponse_readsServerAndLocation() {
        val text = "HTTP/1.1 200 OK\r\n" +
            "CACHE-CONTROL: max-age=1800\r\n" +
            "LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n" +
            "SERVER: Linux/3.14 UPnP/1.0 MiniDLNA/1.2.1\r\n" +
            "ST: ssdp:all\r\n\r\n"
        val info = Ssdp.parseResponse(text)!!
        assertTrue(info.server!!.contains("MiniDLNA"))
        assertEquals("http://192.168.1.1:5000/rootDesc.xml", info.location)
    }

    @Test
    fun ssdp_parseResponse_returnsNullWhenNoIdentifyingHeaders() {
        assertNull(Ssdp.parseResponse("HTTP/1.1 200 OK\r\nDATE: now\r\n\r\n"))
    }

    // --- helpers ---------------------------------------------------------------

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun tlv(tag: Int, content: ByteArray): ByteArray {
        require(content.size < 0x80)
        return byteArrayOf(tag.toByte(), content.size.toByte()) + content
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /** Minimal valid node-status response carrying [names] (name to suffix). */
    private fun buildNbstatResponse(names: List<Pair<String, Int>>): ByteArray {
        val header = bytes(0x12, 0x34, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
        // Echoed question name: 0x20 + 32 encoded bytes + 0x00, then QTYPE + QCLASS.
        val qName = byteArrayOf(0x20) + ByteArray(32) { 'A'.code.toByte() } + byteArrayOf(0x00)
        val question = qName + bytes(0x00, 0x21, 0x00, 0x01)
        // Answer RR name (pointer 0xC00C), TYPE NBSTAT, CLASS IN, TTL, RDLENGTH.
        val rrName = bytes(0xC0, 0x0C)
        val nameBlock = mutableListOf<Byte>()
        nameBlock.add(names.size.toByte())
        for ((n, suffix) in names) {
            val padded = ByteArray(15) { 0x20 }
            val raw = n.toByteArray(Charsets.US_ASCII)
            for (i in 0 until minOf(15, raw.size)) padded[i] = raw[i]
            nameBlock.addAll(padded.toList())
            nameBlock.add(suffix.toByte())
            nameBlock.add(0x04.toByte()) // flags high (unique)
            nameBlock.add(0x00.toByte())
        }
        val rdata = nameBlock.toByteArray()
        val rr = rrName + bytes(0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00) +
            byteArrayOf((rdata.size shr 8).toByte(), (rdata.size and 0xFF).toByte()) + rdata
        return header + question + rr
    }
}
