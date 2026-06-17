package com.watchdog.app.scan.fingerprint

import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

data class HttpResult(
    val status: Int,
    val server: String?,
    val poweredBy: String?,
    val title: String?,
)

/**
 * Probes an HTTP(S) endpoint with OkHttp: reads Server / X-Powered-By and the
 * page title. Follows redirects off so we fingerprint the endpoint itself, not
 * wherever it bounces to. Trusts all TLS certs — we are fingerprinting arbitrary
 * LAN hosts with self-signed certs, not authenticating them.
 */
class HttpProber(private val client: OkHttpClient = defaultClient()) {

    suspend fun probe(ip: String, port: Int, tls: Boolean): HttpResult? {
        val scheme = if (tls) "https" else "http"
        val url = "$scheme://$ip:$port/"
        return try {
            val req = Request.Builder().url(url).header("User-Agent", "watchDog/0.1").get().build()
            client.newCall(req).execute().use { resp ->
                val body = try {
                    resp.peekBody(64 * 1024).string()
                } catch (e: Exception) {
                    null
                }
                HttpResult(
                    status = resp.code,
                    server = resp.header("Server"),
                    poweredBy = resp.header("X-Powered-By"),
                    title = body?.let { extractTitle(it) },
                )
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun extractTitle(html: String): String? =
        Regex("<title[^>]*>(.*?)</title>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(html)?.groupValues?.getOrNull(1)?.trim()?.take(200)?.ifBlank { null }

    companion object {
        fun defaultClient(): OkHttpClient {
            val trustAll = TlsTrust.insecureClientBuilder()
            return trustAll
                .followRedirects(false)
                .followSslRedirects(false)
                .connectTimeout(4, TimeUnit.SECONDS)
                .readTimeout(4, TimeUnit.SECONDS)
                .callTimeout(8, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false)
                .build()
        }
    }
}
