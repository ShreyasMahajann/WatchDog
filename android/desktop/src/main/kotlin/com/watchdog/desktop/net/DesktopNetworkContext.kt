package com.watchdog.desktop.net

import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkContext
import com.watchdog.app.net.NetworkInfo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Desktop (Windows/Linux) implementation of [NetworkContext] using the JVM's
 * [NetworkInterface] API — no Android types. Picks the primary active LAN
 * interface (up, not loopback/virtual, with a site-local IPv4 address) and
 * derives its CIDR from the interface prefix length. SSID is not read on desktop
 * (surfaced as null rather than guessed); the gateway is best-effort from the OS
 * routing table.
 */
class DesktopNetworkContext(
    private val gatewayResolver: () -> String? = ::defaultGateway,
) : NetworkContext {

    override fun current(): NetworkInfo? {
        val candidate = primaryInterface() ?: return null
        val (nif, addr) = candidate
        val ip = addr.address.hostAddress ?: return null
        val prefix = addr.networkPrefixLength.toInt().coerceIn(0, 32)
        val cidr = runCatching { Cidr.of(ip, prefix) }.getOrNull()
        val isWifi = nif.displayName?.lowercase()?.let { name ->
            listOf("wi-fi", "wifi", "wlan", "wireless", "wlp").any { name.contains(it) }
        } ?: false
        return NetworkInfo(
            ssid = null, // desktop SSID lookup is OS-specific; not read in v1
            cidr = cidr,
            localIp = ip,
            gatewayIp = runCatching { gatewayResolver() }.getOrNull(),
            isWifi = isWifi,
        )
    }

    /**
     * Desktop networks change rarely and there is no cheap portable callback, so
     * this emits once and lets the UI re-read [current] on demand (pull to refresh).
     */
    override fun changes(): Flow<Unit> = flow { emit(Unit) }

    private fun primaryInterface(): Pair<NetworkInterface, java.net.InterfaceAddress>? {
        val nifs = runCatching { NetworkInterface.getNetworkInterfaces()?.toList() }.getOrNull().orEmpty()
        val candidates = nifs.mapNotNull { nif ->
            val usable = runCatching { nif.isUp && !nif.isLoopback && !nif.isVirtual }.getOrDefault(false)
            if (!usable) return@mapNotNull null
            val v4 = nif.interfaceAddresses.firstOrNull {
                it.address is Inet4Address && it.address.isSiteLocalAddress
            } ?: return@mapNotNull null
            nif to v4
        }
        // Prefer a wireless interface, then any site-local one.
        return candidates.firstOrNull { (nif, _) ->
            nif.displayName?.lowercase()?.let { n ->
                listOf("wi-fi", "wifi", "wlan", "wireless", "wlp").any { n.contains(it) }
            } ?: false
        } ?: candidates.firstOrNull()
    }

    companion object {
        /** Best-effort default-gateway lookup from the OS routing table; null if unknown. */
        fun defaultGateway(): String? {
            val os = System.getProperty("os.name")?.lowercase().orEmpty()
            return try {
                if (os.contains("win")) gatewayWindows() else gatewayLinux()
            } catch (e: Exception) {
                null
            }
        }

        private fun gatewayLinux(): String? {
            // /proc/net/route: fields Iface Destination Gateway ... ; default route has Destination 00000000.
            val file = java.io.File("/proc/net/route")
            if (!file.exists()) return null
            for (line in file.readLines().drop(1)) {
                val cols = line.split("\t", " ").filter { it.isNotBlank() }
                if (cols.size >= 3 && cols[1] == "00000000") {
                    val hex = cols[2]
                    if (hex.length == 8) {
                        // little-endian hex -> dotted quad
                        val b = hex.chunked(2).map { it.toInt(16) }
                        return "${b[3]}.${b[2]}.${b[1]}.${b[0]}"
                    }
                }
            }
            return null
        }

        private fun gatewayWindows(): String? {
            val proc = ProcessBuilder("cmd", "/c", "route", "print", "0.0.0.0")
                .redirectErrorStream(true).start()
            val text = proc.inputStream.bufferedReader().readText()
            proc.waitFor()
            // Rows: "0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>"
            val ipRegex = Regex("""\d{1,3}(?:\.\d{1,3}){3}""")
            for (line in text.lines()) {
                val t = line.trim()
                if (t.startsWith("0.0.0.0")) {
                    val ips = ipRegex.findAll(t).map { it.value }.toList()
                    // 0.0.0.0, 0.0.0.0, gateway, interface, ...
                    if (ips.size >= 3 && ips[2] != "0.0.0.0") return ips[2]
                }
            }
            return null
        }
    }
}
