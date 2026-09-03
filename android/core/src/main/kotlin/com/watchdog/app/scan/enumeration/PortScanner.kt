package com.watchdog.app.scan.enumeration

import com.watchdog.app.scan.PortState
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.SocketProbe
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/** An open TCP port found on a host. */
data class OpenPort(val port: Int, val serviceHint: String?)

/**
 * Bounded-concurrency connect scan of a single host. Emits each OPEN port as it
 * is found so the UI can fill in live. Closed/filtered ports are dropped.
 * Cancellation propagates through the enclosing coroutineScope; each in-flight
 * connect is closed by SocketProbe's finally block.
 */
class PortScanner {

    fun scan(ip: String, ports: IntArray, config: ScanConfig): Flow<OpenPort> = channelFlow {
        val gate = Semaphore(config.maxConcurrentSockets)
        coroutineScope {
            for (port in ports) {
                launch {
                    gate.withPermit {
                        val state = SocketProbe.probe(ip, port, config.portConnectTimeoutMs)
                        if (state == PortState.OPEN) {
                            send(OpenPort(port, PortSets.serviceHint(port)))
                        }
                    }
                }
            }
        }
    }
}
