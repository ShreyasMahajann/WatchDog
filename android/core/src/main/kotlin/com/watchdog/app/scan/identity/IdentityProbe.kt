package com.watchdog.app.scan.identity

import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.model.ServiceObservation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * A connectionless (UDP) identity probe: sends one datagram to a host and turns a
 * response into a [ServiceObservation]. Returns null when the host doesn't answer
 * — these are best-effort enrichment, never a reason to fail a host's scan.
 */
interface IdentityProbe {
    suspend fun probe(host: String, config: ScanConfig): ServiceObservation?
}

/** One-shot UDP request/response with a timeout. Any failure yields null. */
object UdpProbe {
    suspend fun exchange(
        host: String,
        port: Int,
        payload: ByteArray,
        timeoutMs: Int,
        bufSize: Int = 8192,
    ): ByteArray? = withContext(Dispatchers.IO) {
        val socket = DatagramSocket()
        try {
            socket.soTimeout = timeoutMs
            val addr = InetAddress.getByName(host)
            socket.send(DatagramPacket(payload, payload.size, addr, port))
            val buf = ByteArray(bufSize)
            val resp = DatagramPacket(buf, buf.size)
            socket.receive(resp)
            resp.data.copyOf(resp.length)
        } catch (e: Exception) {
            null
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }
}
