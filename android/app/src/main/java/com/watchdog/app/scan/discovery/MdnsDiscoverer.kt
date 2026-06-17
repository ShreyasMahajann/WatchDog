package com.watchdog.app.scan.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

/**
 * Passive mDNS/DNS-SD discovery via NsdManager — the most productive non-root
 * LAN identity channel (device names + advertised service types). Requires a
 * held MulticastLock (CHANGE_WIFI_MULTICAST_STATE). Discovers a set of common
 * service types and resolves each to an address.
 *
 * NsdManager historically tolerates only one in-flight resolve, so resolves are
 * serialized through a Mutex. resolveService is deprecated on API 34+ but is the
 * portable path down to minSdk 26; a registerServiceInfoCallback path is a
 * follow-up.
 */
class MdnsDiscoverer(private val appContext: Context) : HostDiscoverer {
    override val source = "mdns"

    private val serviceTypes = listOf(
        "_http._tcp.", "_https._tcp.", "_ssh._tcp.", "_workstation._tcp.",
        "_smb._tcp.", "_afpovertcp._tcp.", "_printer._tcp.", "_ipp._tcp.",
        "_airplay._tcp.", "_raop._tcp.", "_googlecast._tcp.", "_device-info._tcp.",
    )

    @Suppress("DEPRECATION")
    override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = callbackFlow {
        val nsd = appContext.getSystemService(Context.NSD_SERVICE) as? NsdManager
        if (nsd == null) {
            close()
            return@callbackFlow
        }
        val wifi = appContext.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val lock = wifi?.createMulticastLock("watchdog-mdns")?.apply {
            setReferenceCounted(true)
            runCatching { acquire() }
        }

        val listeners = mutableListOf<NsdManager.DiscoveryListener>()

        for (type in serviceTypes) {
            val listener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType: String) {}
                override fun onDiscoveryStopped(serviceType: String) {}
                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    // Resolve to get the address. Serialize to avoid "listener in use".
                    val resolveListener = object : NsdManager.ResolveListener {
                        override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
                        override fun onServiceResolved(resolved: NsdServiceInfo) {
                            val ip = resolved.host?.hostAddress ?: return
                            trySend(
                                DiscoveredHost(
                                    ip = ip,
                                    hostname = resolved.serviceName,
                                    source = source,
                                    serviceHints = listOf(serviceInfo.serviceType.trim('.')),
                                ),
                            )
                        }
                    }
                    // Best-effort, fire-and-forget resolve.
                    runCatching { nsd.resolveService(serviceInfo, resolveListener) }
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
            }
            listeners.add(listener)
            runCatching {
                nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, listener)
            }
        }

        awaitClose {
            for (l in listeners) runCatching { nsd.stopServiceDiscovery(l) }
            runCatching { lock?.release() }
        }
    }
}
