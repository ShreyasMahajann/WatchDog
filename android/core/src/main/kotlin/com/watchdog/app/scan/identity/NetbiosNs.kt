package com.watchdog.app.scan.identity

/**
 * NetBIOS Name Service (UDP 137) node-status codec — the classic way to pull a
 * Windows/SMB host's computer name and workgroup without authentication. Pure so
 * the wire format is unit-tested; the socket lives in [NetbiosProbe].
 */
object NetbiosNs {

    /** A single name entry from a node-status response. */
    data class NbName(val name: String, val suffix: Int, val group: Boolean)

    /** Build a node-status ("NBSTAT") query for the wildcard name "*". */
    fun buildNodeStatusQuery(txId: Int): ByteArray {
        val header = byteArrayOf(
            (txId shr 8).toByte(), (txId and 0xFF).toByte(),
            0x00, 0x00, // flags
            0x00, 0x01, // questions
            0x00, 0x00, // answer RRs
            0x00, 0x00, // authority RRs
            0x00, 0x00, // additional RRs
        )
        val question = byteArrayOf(0x20) + encodeName("*") + byteArrayOf(0x00) +
            byteArrayOf(0x00, 0x21) + // QTYPE = NBSTAT
            byteArrayOf(0x00, 0x01) // QCLASS = IN
        return header + question
    }

    /** Parse the names out of a node-status response's RDATA. */
    fun parseNames(resp: ByteArray): List<NbName> {
        // Header(12) + question echo (name + QTYPE(2) + QCLASS(2)), then the answer
        // RR whose RDATA starts with a 1-byte name count followed by 18-byte entries.
        var p = 12
        // Skip the echoed question name (length-prefixed labels, 0x00-terminated).
        p = skipName(resp, p) ?: return emptyList()
        p += 4 // QTYPE + QCLASS
        // Answer RR: name, TYPE(2), CLASS(2), TTL(4), RDLENGTH(2)
        p = skipName(resp, p) ?: return emptyList()
        p += 8 // TYPE + CLASS + TTL
        if (p + 2 > resp.size) return emptyList()
        p += 2 // RDLENGTH
        if (p >= resp.size) return emptyList()
        val count = resp[p].toInt() and 0xFF
        p += 1
        val out = mutableListOf<NbName>()
        repeat(count) {
            if (p + 18 > resp.size) return@repeat
            val name = String(resp.copyOfRange(p, p + 15), Charsets.US_ASCII).trim()
            val suffix = resp[p + 15].toInt() and 0xFF
            val flags = ((resp[p + 16].toInt() and 0xFF) shl 8) or (resp[p + 17].toInt() and 0xFF)
            val group = (flags and 0x8000) != 0
            if (name.isNotBlank()) out.add(NbName(name, suffix, group))
            p += 18
        }
        return out
    }

    /** The unique workstation name (suffix 0x00, not a group) if present. */
    fun hostnameOf(names: List<NbName>): String? =
        names.firstOrNull { it.suffix == 0x00 && !it.group }?.name

    // NetBIOS "first-level encoding": each byte → two nibbles, each + 'A'. The
    // 16-byte name is the value padded with spaces (0x20) to 15 + a 1-byte suffix.
    private fun encodeName(name: String, suffix: Int = 0x00): ByteArray {
        val padded = ByteArray(16) { 0x20 }
        val raw = name.toByteArray(Charsets.US_ASCII)
        for (i in 0 until minOf(15, raw.size)) padded[i] = raw[i]
        padded[15] = suffix.toByte()
        val out = ByteArray(32)
        for (i in 0 until 16) {
            val b = padded[i].toInt() and 0xFF
            out[i * 2] = ('A'.code + (b shr 4)).toByte()
            out[i * 2 + 1] = ('A'.code + (b and 0x0F)).toByte()
        }
        return out
    }

    private fun skipName(b: ByteArray, pos: Int): Int? {
        var p = pos
        while (p < b.size) {
            val len = b[p].toInt() and 0xFF
            if (len == 0) return p + 1
            // A compression pointer (top two bits set) is a 2-byte terminal reference.
            if ((len and 0xC0) == 0xC0) return if (p + 2 <= b.size) p + 2 else null
            p += 1 + len
        }
        return null
    }
}
