package com.watchdog.app.wpa.handshake

/** One captured frame: its link-layer type and the raw bytes (still including any radiotap/PPI header). */
internal data class RawPacket(val linkType: Int, val payload: ByteArray)

/** Thrown when the bytes are neither a pcap nor a pcapng file. */
class NotAPcapException(message: String) : Exception(message)

/**
 * Reads classic **pcap** and **pcapng** capture files into a flat list of [RawPacket]s. Endianness
 * is taken from the file's own magic/byte-order marker. Truncated trailing bytes are ignored rather
 * than throwing, so a capture cut off mid-write still yields the frames it did contain.
 */
internal object PcapReader {

    private const val PCAPNG_SHB = 0x0A0D0D0AL
    private const val PCAPNG_IDB = 0x00000001L
    private const val PCAPNG_SPB = 0x00000003L
    private const val PCAPNG_EPB = 0x00000006L

    fun read(data: ByteArray): List<RawPacket> {
        if (data.size < 24) throw NotAPcapException("File too small to be a capture (${data.size} bytes).")
        // pcapng section header block starts with 0A 0D 0D 0A (endian-agnostic).
        if (data[0].toInt() and 0xFF == 0x0A && data[1].toInt() and 0xFF == 0x0D &&
            data[2].toInt() and 0xFF == 0x0D && data[3].toInt() and 0xFF == 0x0A
        ) {
            return readPcapng(data)
        }
        return readClassicPcap(data)
    }

    private fun readClassicPcap(data: ByteArray): List<RawPacket> {
        val b0 = data[0].toInt() and 0xFF
        val b1 = data[1].toInt() and 0xFF
        val b2 = data[2].toInt() and 0xFF
        val b3 = data[3].toInt() and 0xFF
        val littleEndian = when {
            b0 == 0xD4 && b1 == 0xC3 && b2 == 0xB2 && b3 == 0xA1 -> true   // µs, LE
            b0 == 0x4D && b1 == 0x3C && b2 == 0xB2 && b3 == 0xA1 -> true   // ns, LE
            b0 == 0xA1 && b1 == 0xB2 && b2 == 0xC3 && b3 == 0xD4 -> false  // µs, BE
            b0 == 0xA1 && b1 == 0xB2 && b2 == 0x3C && b3 == 0x4D -> false  // ns, BE
            else -> throw NotAPcapException("Unrecognized pcap magic ${"%02x%02x%02x%02x".format(b0, b1, b2, b3)}.")
        }
        val r = ByteReader(data, pos = 0, littleEndian = littleEndian)
        r.skip(4)                 // magic
        r.skip(4)                 // version major/minor
        r.skip(4)                 // thiszone
        r.skip(4)                 // sigfigs
        r.skip(4)                 // snaplen
        val network = r.u32().toInt()

        val out = ArrayList<RawPacket>()
        while (r.hasRemaining(16)) {
            r.skip(4)             // ts sec
            r.skip(4)             // ts usec
            val inclLen = r.u32().toInt()
            r.skip(4)             // orig len
            if (inclLen < 0 || !r.hasRemaining(inclLen)) break
            out.add(RawPacket(network, r.bytes(inclLen)))
        }
        return out
    }

    private fun readPcapng(data: ByteArray): List<RawPacket> {
        var le = true
        val interfaceLinkTypes = ArrayList<Int>()
        val out = ArrayList<RawPacket>()
        var pos = 0

        while (pos + 12 <= data.size) {
            val blockStart = pos
            // Detect a section header block and (re)read the byte-order magic for endianness.
            val isShb = (data[pos].toInt() and 0xFF) == 0x0A && (data[pos + 1].toInt() and 0xFF) == 0x0D &&
                (data[pos + 2].toInt() and 0xFF) == 0x0D && (data[pos + 3].toInt() and 0xFF) == 0x0A
            if (isShb) {
                val bom0 = data[pos + 8].toInt() and 0xFF
                le = bom0 == 0x4D // 4D 3C 2B 1A => little-endian; 1A 2B 3C 4D => big-endian
            }
            val r = ByteReader(data, pos, le)
            val blockType = r.u32()
            val blockTotalLen = r.u32().toInt()
            if (blockTotalLen < 12 || blockStart + blockTotalLen > data.size) break

            when (blockType) {
                PCAPNG_IDB -> {
                    val linkType = r.u16()
                    interfaceLinkTypes.add(linkType)
                }
                PCAPNG_EPB -> {
                    val ifaceId = r.u32().toInt()
                    r.skip(8) // timestamp high/low
                    val capturedLen = r.u32().toInt()
                    r.skip(4) // original len
                    if (capturedLen in 0..(blockTotalLen - 32) && r.hasRemaining(capturedLen)) {
                        val linkType = interfaceLinkTypes.getOrElse(ifaceId) { interfaceLinkTypes.firstOrNull() ?: -1 }
                        out.add(RawPacket(linkType, r.bytes(capturedLen)))
                    }
                }
                PCAPNG_SPB -> {
                    r.skip(4) // original len
                    val avail = blockTotalLen - 16
                    if (avail > 0 && r.hasRemaining(avail)) {
                        val linkType = interfaceLinkTypes.firstOrNull() ?: -1
                        out.add(RawPacket(linkType, r.bytes(avail)))
                    }
                }
                PCAPNG_SHB -> Unit // nothing else we need from the section header
            }
            pos = blockStart + blockTotalLen
        }
        return out
    }
}
