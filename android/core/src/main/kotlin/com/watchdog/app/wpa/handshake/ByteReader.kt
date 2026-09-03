package com.watchdog.app.wpa.handshake

/**
 * Endian-aware cursor over a byte array. All multi-byte reads honor [littleEndian]; helpers that
 * are fixed-endian by spec (radiotap length, EAPOL fields) read explicitly. Bounds are checked so
 * a truncated/corrupt capture throws a clean [IndexOutOfBoundsException] the caller can catch.
 */
internal class ByteReader(val data: ByteArray, var pos: Int = 0, var littleEndian: Boolean = true) {

    val remaining: Int get() = data.size - pos

    fun hasRemaining(n: Int = 1): Boolean = remaining >= n

    fun u8(): Int = data[pos++].toInt() and 0xFF

    fun u16(): Int {
        val b0 = data[pos].toInt() and 0xFF
        val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return if (littleEndian) (b1 shl 8) or b0 else (b0 shl 8) or b1
    }

    fun u32(): Long {
        val bytes = IntArray(4) { data[pos + it].toInt() and 0xFF }
        pos += 4
        return if (littleEndian) {
            (bytes[3].toLong() shl 24) or (bytes[2].toLong() shl 16) or (bytes[1].toLong() shl 8) or bytes[0].toLong()
        } else {
            (bytes[0].toLong() shl 24) or (bytes[1].toLong() shl 16) or (bytes[2].toLong() shl 8) or bytes[3].toLong()
        }
    }

    /** Big-endian u16, regardless of [littleEndian] — for network-order fields (EAPOL, radiotap payloads). */
    fun u16be(): Int {
        val b0 = data[pos].toInt() and 0xFF
        val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return (b0 shl 8) or b1
    }

    /** Little-endian u16, regardless of [littleEndian] — radiotap is always LE. */
    fun u16le(): Int {
        val b0 = data[pos].toInt() and 0xFF
        val b1 = data[pos + 1].toInt() and 0xFF
        pos += 2
        return (b1 shl 8) or b0
    }

    fun bytes(n: Int): ByteArray {
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun skip(n: Int) { pos += n }
}

/** Format a 6-byte MAC as lowercase colon-separated hex (e.g. "a4:2b:8c:00:11:22"). */
internal fun ByteArray.macString(): String =
    joinToString(":") { "%02x".format(it.toInt() and 0xFF) }
