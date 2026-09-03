package com.watchdog.app.net

// Pure IPv4 CIDR math — no android.* imports, so it's JVM-unit-testable.
// Used to turn the phone's LinkAddress (e.g. 192.168.1.37/24) into the list of
// host addresses to probe.

data class Cidr(val networkAddr: Long, val prefixLength: Int) {

    /** Total addresses in the block (including network + broadcast). */
    val size: Long get() = 1L shl (32 - prefixLength)

    /** Broadcast address as a 32-bit value. */
    val broadcastAddr: Long get() = networkAddr + size - 1

    /**
     * Scannable host addresses. For /31 and /32 there is no network/broadcast
     * convention worth excluding, so all addresses are returned; otherwise the
     * network and broadcast addresses are skipped.
     */
    fun hosts(): Sequence<String> {
        val first: Long
        val last: Long
        if (prefixLength >= 31) {
            first = networkAddr
            last = broadcastAddr
        } else {
            first = networkAddr + 1
            last = broadcastAddr - 1
        }
        return (first..last).asSequence().map { longToIp(it) }
    }

    /** Number of host addresses hosts() would yield. */
    val hostCount: Long
        get() = if (prefixLength >= 31) size else (size - 2).coerceAtLeast(0)

    companion object {
        fun of(address: String, prefixLength: Int): Cidr {
            require(prefixLength in 0..32) { "prefix out of range: $prefixLength" }
            val ip = ipToLong(address)
            val mask = if (prefixLength == 0) 0L else (0xFFFFFFFFL shl (32 - prefixLength)) and 0xFFFFFFFFL
            return Cidr(ip and mask, prefixLength)
        }

        fun ipToLong(ip: String): Long {
            val parts = ip.trim().split(".")
            require(parts.size == 4) { "not an IPv4 address: $ip" }
            var result = 0L
            for (p in parts) {
                val octet = p.toInt()
                require(octet in 0..255) { "octet out of range in $ip" }
                result = (result shl 8) or octet.toLong()
            }
            return result
        }

        fun longToIp(value: Long): String {
            val v = value and 0xFFFFFFFFL
            return "${(v shr 24) and 0xFF}.${(v shr 16) and 0xFF}.${(v shr 8) and 0xFF}.${v and 0xFF}"
        }
    }
}
