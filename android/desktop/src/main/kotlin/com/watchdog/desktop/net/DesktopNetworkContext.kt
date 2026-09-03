package com.watchdog.desktop.net

import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkContext
import com.watchdog.app.net.NetworkInfo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.net.Inet4Address
import java.net.InterfaceAddress
import java.net.NetworkInterface

/** A selectable network adapter, for the desktop interface picker. */
data class NetChoice(
    val id: String,          // interface name (e.g. "wlan0", "eth0", "Wi-Fi")
    val displayName: String,
    val ip: String,
    val prefixLength: Int,
    val isWifi: Boolean,
) {
    val label: String get() = "${displayName.ifBlank { id }}  ·  $ip/$prefixLength" + if (isWifi) "  (Wi-Fi)" else ""
}

/**
 * Desktop (Windows/Linux) implementation of [NetworkContext] using the JVM's
 * [NetworkInterface] API — no Android types. When more than one adapter is active
 * the user can [select] which one to scan; otherwise a Wi-Fi-preferred auto-pick is
 * used. Derives the CIDR from the chosen interface's prefix length.
 */
class DesktopNetworkContext(
    private val gatewayResolver: () -> String? = ::defaultGateway,
) : NetworkContext {

    @Volatile
    private var selectedId: String? = null

    /** Force a specific adapter (by interface name), or null to auto-pick. */
    fun select(id: String?) { selectedId = id }
    fun selectedId(): String? = selectedId

    /** All active, scannable adapters (up, non-loopback, with a site-local IPv4). */
    fun interfaces(): List<NetChoice> = candidates().map { (nif, addr) ->
        NetChoice(
            id = nif.name,
            displayName = nif.displayName ?: nif.name,
            ip = addr.address.hostAddress ?: "?",
            prefixLength = addr.networkPrefixLength.toInt().coerceIn(0, 32),
            isWifi = nif.isWifiName(),
        )
    }

    override fun current(): NetworkInfo? {
        val candidate = chosenInterface() ?: return null
        val (nif, addr) = candidate
        val ip = addr.address.hostAddress ?: return null
        val prefix = addr.networkPrefixLength.toInt().coerceIn(0, 32)
        val cidr = runCatching { Cidr.of(ip, prefix) }.getOrNull()
        return NetworkInfo(
            ssid = null, // desktop SSID lookup is OS-specific; not read in v1
            cidr = cidr,
            localIp = ip,
            gatewayIp = runCatching { gatewayResolver() }.getOrNull(),
            isWifi = nif.isWifiName(),
        )
    }

    override fun changes(): Flow<Unit> = flow { emit(Unit) }

    private fun chosenInterface(): Pair<NetworkInterface, InterfaceAddress>? {
        val all = candidates()
        selectedId?.let { id -> all.firstOrNull { it.first.name == id }?.let { return it } }
        // Auto: prefer a wireless adapter, else the first site-local one.
        return all.firstOrNull { it.first.isWifiName() } ?: all.firstOrNull()
    }

    private fun candidates(): List<Pair<NetworkInterface, InterfaceAddress>> {
        val nifs = runCatching { NetworkInterface.getNetworkInterfaces()?.toList() }.getOrNull().orEmpty()
        return nifs.mapNotNull { nif ->
            val usable = runCatching { nif.isUp && !nif.isLoopback && !nif.isVirtual }.getOrDefault(false)
            if (!usable) return@mapNotNull null
            val v4 = nif.interfaceAddresses.firstOrNull {
                it.address is Inet4Address && it.address.isSiteLocalAddress
            } ?: return@mapNotNull null
            nif to v4
        }
    }

    private fun NetworkInterface.isWifiName(): Boolean =
        (displayName ?: name).lowercase().let { n ->
            listOf("wi-fi", "wifi", "wlan", "wireless", "wlp").any { n.contains(it) }
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
            val file = java.io.File("/proc/net/route")
            if (!file.exists()) return null
            for (line in file.readLines().drop(1)) {
                val cols = line.split("\t", " ").filter { it.isNotBlank() }
                if (cols.size >= 3 && cols[1] == "00000000") {
                    val hex = cols[2]
                    if (hex.length == 8) {
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
            val ipRegex = Regex("""\d{1,3}(?:\.\d{1,3}){3}""")
            for (line in text.lines()) {
                val t = line.trim()
                if (t.startsWith("0.0.0.0")) {
                    val ips = ipRegex.findAll(t).map { it.value }.toList()
                    if (ips.size >= 3 && ips[2] != "0.0.0.0") return ips[2]
                }
            }
            return null
        }
    }
}
