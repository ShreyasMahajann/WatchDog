package com.watchdog.app.wpa.device

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class ToolInfo(val name: String, val path: String?) {
    val present: Boolean get() = path != null
}

/**
 * Checks whether the command-line userland needed for capture is present on the device.
 * Stock Android ships none of these, so absence is the norm — the capture milestone would
 * bundle its own binaries. We report the true state here rather than assuming.
 */
object ToolProbe {

    private val CAPTURE_TOOLS = listOf("tcpdump", "iw", "airmon-ng", "airodump-ng")

    suspend fun probe(): List<ToolInfo> = withContext(Dispatchers.IO) {
        CAPTURE_TOOLS.map { ToolInfo(it, Shell.which(it)) }
    }
}
