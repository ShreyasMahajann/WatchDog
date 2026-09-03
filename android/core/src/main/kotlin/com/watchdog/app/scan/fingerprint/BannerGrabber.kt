package com.watchdog.app.scan.fingerprint

import com.watchdog.app.scan.ScanConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Grabs a plaintext banner from a server-speaks-first service (SSH/FTP/SMTP/…).
 * Opens a raw socket, reads what the server volunteers within the read timeout,
 * and returns it. For services that expect the client to speak first (bare
 * HTTP), it optionally sends a minimal nudge. Never throws — returns null on any
 * failure so one dead port can't abort a scan.
 */
class BannerGrabber {

    suspend fun grab(ip: String, port: Int, config: ScanConfig, nudge: ByteArray? = null): String? =
        withContext(Dispatchers.IO) {
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(ip, port), config.portConnectTimeoutMs)
                socket.soTimeout = config.bannerReadTimeoutMs
                if (nudge != null) {
                    socket.getOutputStream().apply {
                        write(nudge)
                        flush()
                    }
                }
                val buf = ByteArray(2048)
                val n = try {
                    socket.getInputStream().read(buf)
                } catch (e: IOException) {
                    -1
                }
                if (n <= 0) null else String(buf, 0, n, Charsets.ISO_8859_1).trim().ifBlank { null }
            } catch (e: IOException) {
                null
            } finally {
                try {
                    socket.close()
                } catch (_: IOException) {
                }
            }
        }
}
