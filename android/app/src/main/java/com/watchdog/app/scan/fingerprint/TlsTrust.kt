package com.watchdog.app.scan.fingerprint

import okhttp3.OkHttpClient
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * All-trusting TLS for fingerprinting only. We connect to arbitrary LAN hosts
 * that legitimately use self-signed / mismatched certs; the goal is to READ the
 * certificate and negotiated parameters, not to authenticate the peer. This
 * trust manager is used exclusively by the scan probers and never for the
 * app's own backend calls (those go through OkHttp's default trust).
 */
object TlsTrust {

    val trustManager: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun socketFactory(): SSLSocketFactory {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustManager), java.security.SecureRandom())
        return ctx.socketFactory
    }

    fun insecureClientBuilder(): OkHttpClient.Builder =
        OkHttpClient.Builder()
            .sslSocketFactory(socketFactory(), trustManager)
            .hostnameVerifier { _, _ -> true }
}
