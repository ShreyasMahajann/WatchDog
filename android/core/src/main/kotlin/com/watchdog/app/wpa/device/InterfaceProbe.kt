package com.watchdog.app.wpa.device

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.NetworkInterface

data class InterfaceInfo(
    val name: String,
    val isUp: Boolean,
    val hasHardwareAddr: Boolean,
    /** True if the interface looks like an 802.11 monitor interface (name or ARPHRD type). */
    val looksMonitor: Boolean,
)

/**
 * Enumerates network interfaces from both the JVM API and `/sys/class/net` (which surfaces
 * interfaces the JVM view can miss, e.g. a freshly created `wlan0mon`). A monitor interface
 * is recognized either by name convention (`*mon`) or ARPHRD type 803 (IEEE80211_RADIOTAP).
 */
object InterfaceProbe {

    private const val ARPHRD_IEEE80211_RADIOTAP = 803

    suspend fun list(): List<InterfaceInfo> = withContext(Dispatchers.IO) {
        val fromSys = sysClassNet()
        val fromJvm = jvmInterfaces()
        // Merge by name; JVM entries carry up/hwaddr state, /sys fills in the rest.
        val names = (fromSys.keys + fromJvm.keys).sorted()
        names.map { name ->
            val jvm = fromJvm[name]
            val sysType = fromSys[name]
            val looksMonitor = name.contains("mon") || sysType == ARPHRD_IEEE80211_RADIOTAP
            InterfaceInfo(
                name = name,
                isUp = jvm?.isUp ?: false,
                hasHardwareAddr = jvm?.hasHwAddr ?: false,
                looksMonitor = looksMonitor,
            )
        }
    }

    private data class JvmIface(val isUp: Boolean, val hasHwAddr: Boolean)

    private fun jvmInterfaces(): Map<String, JvmIface> =
        runCatching {
            NetworkInterface.getNetworkInterfaces().asSequence().associate { ni ->
                ni.name to JvmIface(
                    isUp = runCatching { ni.isUp }.getOrDefault(false),
                    hasHwAddr = runCatching { ni.hardwareAddress != null }.getOrDefault(false),
                )
            }
        }.getOrDefault(emptyMap())

    /** Interface name -> ARPHRD type from /sys/class/net/<n>/type (null if unreadable). */
    private fun sysClassNet(): Map<String, Int?> =
        runCatching {
            File("/sys/class/net").listFiles().orEmpty().associate { dir ->
                dir.name to runCatching { File(dir, "type").readText().trim().toInt() }.getOrNull()
            }
        }.getOrDefault(emptyMap())
}
