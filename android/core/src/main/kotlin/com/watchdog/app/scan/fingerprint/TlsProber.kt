package com.watchdog.app.scan.fingerprint

import com.watchdog.app.scan.ScanConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket

data class TlsInfo(
    val protocol: String?,
    val cipher: String?,
    val subject: String?,
    val issuer: String?,
    val notAfter: String?,
)

/**
 * Opens a TLS connection, completes the handshake, and reads the negotiated
 * version/cipher plus the leaf certificate's subject/issuer/expiry. Trusts all
 * certs (see TlsTrust) because the point is to observe, not authenticate.
 */
class TlsProber {

    suspend fun probe(ip: String, port: Int, config: ScanConfig): TlsInfo? =
        withContext(Dispatchers.IO) {
            val raw = Socket()
            try {
                raw.connect(InetSocketAddress(ip, port), config.portConnectTimeoutMs)
                val factory = TlsTrust.socketFactory()
                val ssl = factory.createSocket(raw, ip, port, true) as SSLSocket
                ssl.soTimeout = config.bannerReadTimeoutMs
                ssl.startHandshake()
                val session = ssl.session
                val leaf = session.peerCertificates.firstOrNull() as? X509Certificate
                TlsInfo(
                    protocol = session.protocol,
                    cipher = session.cipherSuite,
                    subject = leaf?.subjectX500Principal?.name,
                    issuer = leaf?.issuerX500Principal?.name,
                    notAfter = leaf?.notAfter?.toInstant()?.toString(),
                ).also { runCatching { ssl.close() } }
            } catch (e: Exception) {
                null
            } finally {
                runCatching { raw.close() }
            }
        }
}
