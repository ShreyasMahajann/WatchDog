package com.watchdog.app.scan.identity

/**
 * Minimal SNMPv1 codec — just enough to ask a host for sysDescr.0 and read the
 * string back. Pure (no sockets) so the BER encode/decode is unit-tested.
 *
 * A GET request is a nested BER structure:
 *   SEQUENCE { version(0), community, GetRequest[A0]{ reqId, 0, 0,
 *              SEQUENCE{ SEQUENCE{ OID(sysDescr.0), NULL } } } }
 * The response echoes it as a GetResponse[A2] with the OID's value filled in.
 */
object SnmpV1 {

    // 1.3.6.1.2.1.1.1.0 — system.sysDescr.0
    val SYS_DESCR_OID = intArrayOf(1, 3, 6, 1, 2, 1, 1, 1, 0)

    fun buildGet(community: String, requestId: Int, oid: IntArray = SYS_DESCR_OID): ByteArray {
        val varbind = tlv(0x30, encodeOid(oid) + tlv(0x05, ByteArray(0))) // OID + NULL
        val varbindList = tlv(0x30, varbind)
        val pdu = tlv(
            0xA0, // GetRequest-PDU
            integer(requestId) + integer(0) + integer(0) + varbindList,
        )
        val body = integer(0) + tlv(0x04, community.toByteArray(Charsets.US_ASCII)) + pdu
        return tlv(0x30, body)
    }

    /** Extract the first OCTET STRING value from a GetResponse (the sysDescr). */
    fun parseSysDescr(resp: ByteArray): String? {
        var p = 0
        val outer = readTlv(resp, p) ?: return null
        if (outer.tag != 0x30) return null
        p = outer.contentStart
        p = skip(resp, p) ?: return null // version
        p = skip(resp, p) ?: return null // community
        val pdu = readTlv(resp, p) ?: return null // GetResponse [A2]
        p = pdu.contentStart
        repeat(3) { p = skip(resp, p) ?: return null } // reqId, error-status, error-index
        val list = readTlv(resp, p) ?: return null
        p = list.contentStart
        val vb = readTlv(resp, p) ?: return null
        p = vb.contentStart
        p = skip(resp, p) ?: return null // OID
        val value = readTlv(resp, p) ?: return null
        if (value.tag != 0x04) return null // must be an OCTET STRING
        return String(resp.copyOfRange(value.contentStart, value.contentEnd), Charsets.ISO_8859_1)
            .trim().ifBlank { null }
    }

    // --- BER helpers -----------------------------------------------------------

    private data class Tlv(val tag: Int, val contentStart: Int, val contentEnd: Int)

    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + lengthBytes(content.size) + content

    private fun lengthBytes(n: Int): ByteArray {
        if (n < 0x80) return byteArrayOf(n.toByte())
        val bytes = mutableListOf<Byte>()
        var v = n
        while (v > 0) { bytes.add(0, (v and 0xFF).toByte()); v = v ushr 8 }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    private fun integer(v: Int): ByteArray {
        val bytes = mutableListOf<Byte>()
        var value = v
        if (value == 0) return byteArrayOf(0x02, 0x01, 0x00)
        while (value != 0 && value != -1) { bytes.add(0, (value and 0xFF).toByte()); value = value shr 8 }
        if (v > 0 && (bytes[0].toInt() and 0x80) != 0) bytes.add(0, 0)
        return byteArrayOf(0x02) + lengthBytes(bytes.size) + bytes.toByteArray()
    }

    private fun encodeOid(oid: IntArray): ByteArray {
        require(oid.size >= 2)
        val out = mutableListOf<Byte>()
        out.add((40 * oid[0] + oid[1]).toByte())
        for (i in 2 until oid.size) out.addAll(base128(oid[i]).toList())
        return tlv(0x06, out.toByteArray())
    }

    private fun base128(value: Int): ByteArray {
        if (value < 0x80) return byteArrayOf(value.toByte())
        val stack = mutableListOf<Int>()
        var v = value
        while (v > 0) { stack.add(0, v and 0x7F); v = v ushr 7 }
        return ByteArray(stack.size) { i ->
            val last = i == stack.size - 1
            ((if (last) 0 else 0x80) or stack[i]).toByte()
        }
    }

    /** Read a tag + (short/long-form) length at [pos]; null if malformed/truncated. */
    private fun readTlv(b: ByteArray, pos: Int): Tlv? {
        if (pos + 1 >= b.size) return null
        val tag = b[pos].toInt() and 0xFF
        var p = pos + 1
        val first = b[p].toInt() and 0xFF
        p += 1
        val len: Int
        if (first < 0x80) {
            len = first
        } else {
            val n = first and 0x7F
            if (n == 0 || p + n > b.size) return null
            var acc = 0
            repeat(n) { acc = (acc shl 8) or (b[p].toInt() and 0xFF); p += 1 }
            len = acc
        }
        val end = p + len
        if (end > b.size) return null
        return Tlv(tag, p, end)
    }

    private fun skip(b: ByteArray, pos: Int): Int? = readTlv(b, pos)?.contentEnd
}
