package com.watchdog.app.share

import android.content.Context
import android.content.Intent
import com.watchdog.app.data.room.HostEntity
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation

/** Builds shareable plain-text reports and fires the Android share sheet. */
object ScanShare {

    fun deviceText(host: String, obs: List<ServiceObservation>, findings: List<Finding>): String = buildString {
        appendLine("Device $host")
        appendLine("Services:")
        obs.forEach { o ->
            val prod = o.product?.let { " ${it.product}${it.version?.let { v -> " $v" } ?: ""}" } ?: ""
            appendLine("  ${o.port}/${o.proto} ${o.serviceName ?: ""}$prod".trimEnd())
        }
        if (findings.isNotEmpty()) {
            appendLine("Findings:")
            findings.forEach { f -> appendLine("  ${f.severity} ${f.cveId} ${f.product.product} ${f.host}:${f.port}") }
        }
    }

    fun reportText(hosts: List<HostEntity>, obs: List<ServiceObservation>, findings: List<Finding>): String = buildString {
        appendLine("watchDog scan report")
        appendLine("${hosts.size} devices, ${obs.size} services, ${findings.size} findings")
        appendLine()
        hosts.forEach { h ->
            appendLine(deviceText(h.ip, obs.filter { it.host == h.ip }, findings.filter { it.host == h.ip }))
        }
    }

    fun share(context: Context, text: String) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(
            Intent.createChooser(send, "Share").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }
}
