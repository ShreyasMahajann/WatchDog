package com.watchdog.app.scan

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.Socket
import java.net.SocketTimeoutException

/** Result of a single TCP connect attempt. */
enum class PortState {
    OPEN, // completed handshake
    CLOSED, // host answered with RST (connection refused) — host is alive
    FILTERED, // no answer within the timeout, or unreachable
}

object SocketProbe {

    /**
     * Non-blocking-friendly connect probe on Dispatchers.IO. A refused (RST)
     * connection still proves the host is alive, so callers doing host
     * discovery treat both OPEN and CLOSED as "alive".
     */
    suspend fun probe(ip: String, port: Int, timeoutMs: Int): PortState =
        withContext(Dispatchers.IO) {
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                PortState.OPEN
            } catch (e: SocketTimeoutException) {
                PortState.FILTERED
            } catch (e: ConnectException) {
                // "Connection refused" => reachable host, closed port.
                PortState.CLOSED
            } catch (e: NoRouteToHostException) {
                PortState.FILTERED
            } catch (e: PortUnreachableException) {
                PortState.FILTERED
            } catch (e: IOException) {
                PortState.FILTERED
            } finally {
                try {
                    socket.close()
                } catch (_: IOException) {
                }
            }
        }
}
