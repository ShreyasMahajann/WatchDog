package com.watchdog.app.scan.identity

/**
 * SSDP (UPnP discovery, UDP 1900) request builder + response parser. Pure so the
 * HTTP-over-UDP formatting is unit-tested; the socket lives in [SsdpProbe].
 */
object Ssdp {

    data class SsdpInfo(val server: String?, val location: String?, val st: String?, val usn: String?)

    /** A unicast M-SEARCH aimed at one host — many UPnP devices answer directly. */
    fun buildMSearch(host: String, port: Int = 1900, mx: Int = 1): ByteArray =
        (
            "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: $host:$port\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: $mx\r\n" +
                "ST: ssdp:all\r\n" +
                "\r\n"
            ).toByteArray(Charsets.US_ASCII)

    /** Parse the HTTP-style headers of an SSDP response. Returns null if empty. */
    fun parseResponse(text: String): SsdpInfo? {
        val headers = HashMap<String, String>()
        for (line in text.split("\r\n", "\n")) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            val key = line.substring(0, idx).trim().uppercase()
            val value = line.substring(idx + 1).trim()
            if (value.isNotEmpty()) headers.putIfAbsent(key, value)
        }
        val info = SsdpInfo(
            server = headers["SERVER"],
            location = headers["LOCATION"],
            st = headers["ST"],
            usn = headers["USN"],
        )
        return if (info.server == null && info.location == null && info.usn == null) null else info
    }
}
