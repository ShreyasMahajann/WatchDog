package com.watchdog.app.wpa.capture

import android.content.Context
import com.watchdog.app.wpa.device.RootProbe
import com.watchdog.app.wpa.device.RootStatus
import com.watchdog.app.wpa.device.Shell
import com.watchdog.app.wpa.handshake.HandshakeAnalysis
import com.watchdog.app.wpa.handshake.HandshakeAnalyzer
import com.watchdog.app.wpa.storage.CaptureStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Parameters for a root capture run. */
data class CaptureParams(
    /** The managed interface to convert (e.g. "wlan0" or "wlan1" for a USB adapter). */
    val iface: String,
    /** Monitor interface name to capture on once enabled (e.g. "wlan0mon" or the same iface). */
    val monitorIface: String,
    val channel: Int?,
    val durationSec: Int,
    val label: String,
)

sealed interface CaptureResult {
    data class Success(val filePath: String, val analysis: HandshakeAnalysis) : CaptureResult
    data class Failure(val reason: String) : CaptureResult
}

/**
 * Real on-device capture for rooted, monitor-capable devices. It enables monitor mode and runs
 * `tcpdump` via a root shell, then validates the resulting pcap with the same analyzer used for
 * imports. This path is **gated**: callers must only invoke it when the capability model says
 * capture is possible, and the engine itself re-checks root and fails cleanly otherwise — it never
 * fabricates a capture. On the typical non-root phone this simply returns [CaptureResult.Failure].
 */
class RootCaptureEngine(context: Context) {

    private val store = CaptureStore(context)

    suspend fun capture(params: CaptureParams): CaptureResult = withContext(Dispatchers.IO) {
        val root = RootProbe.detect(activeCheck = true)
        if (root.status != RootStatus.GRANTED) {
            return@withContext CaptureResult.Failure("Root shell not granted — cannot enable monitor mode.")
        }

        val out = File(store.dir, "capture_${params.label}.pcap")
        val outPath = out.absolutePath
        val channelCmd = params.channel?.let { "iw dev ${params.monitorIface} set channel $it 2>/dev/null; " } ?: ""

        // Enable monitor mode (iw first, airmon-ng as fallback), set channel, capture, then restore.
        val script = buildString {
            append("iw dev ${params.iface} set type monitor 2>/dev/null || airmon-ng start ${params.iface} >/dev/null 2>&1; ")
            append("ip link set ${params.monitorIface} up 2>/dev/null; ")
            append(channelCmd)
            append("timeout ${params.durationSec} tcpdump -i ${params.monitorIface} -w '$outPath' 2>/dev/null; ")
            append("chmod 666 '$outPath' 2>/dev/null; ")
            append("iw dev ${params.monitorIface} set type managed 2>/dev/null; ")
            append("ip link set ${params.iface} up 2>/dev/null")
        }

        val res = Shell.run(listOf("su", "-c", script), timeoutMs = (params.durationSec + 20) * 1000L)
        if (!out.exists() || out.length() == 0L) {
            return@withContext CaptureResult.Failure(
                "No capture produced. Monitor mode or tcpdump likely unavailable. ${res.text.take(180)}".trim(),
            )
        }
        val analysis = runCatching { HandshakeAnalyzer.analyze(out.readBytes()) }
            .getOrElse { return@withContext CaptureResult.Failure("Capture file could not be parsed: ${it.message}") }
        CaptureResult.Success(outPath, analysis)
    }
}
