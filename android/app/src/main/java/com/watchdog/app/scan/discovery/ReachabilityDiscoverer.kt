package com.watchdog.app.scan.discovery

import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * Best-effort ICMP-style liveness via InetAddress.isReachable. On unrooted
 * Android there is no raw-ICMP permission, so this quietly degrades to a
 * TCP-echo probe and mostly returns false — it's a bonus signal, never
 * authoritative. TcpProbeDiscoverer is the real workhorse.
 */
class ReachabilityDiscoverer : HostDiscoverer {
    override val source = "icmp"

    override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = channelFlow {
        val gate = Semaphore(config.maxConcurrentSockets)
        coroutineScope {
            for (ip in cidr.hosts()) {
                launch {
                    gate.withPermit {
                        if (isReachable(ip, config.discoveryProbeTimeoutMs)) {
                            send(DiscoveredHost(ip = ip, source = source))
                        }
                    }
                }
            }
        }
    }

    private suspend fun isReachable(ip: String, timeoutMs: Int): Boolean =
        withContext(Dispatchers.IO) {
            try {
                InetAddress.getByName(ip).isReachable(timeoutMs)
            } catch (e: Exception) {
                false
            }
        }
}
