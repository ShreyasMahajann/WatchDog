package com.watchdog.app.wpa.diagnostics

import com.watchdog.app.wpa.device.CapabilityAssessment
import com.watchdog.app.wpa.device.IdentifiedAdapter
import com.watchdog.app.wpa.device.InterfaceInfo
import com.watchdog.app.wpa.device.RootResult
import com.watchdog.app.wpa.device.ToolInfo

/**
 * A full snapshot of what the device actually reports, for the diagnostics screen. Every field
 * is populated from a real probe; `errors` collects anything that failed so the UI can surface
 * it rather than silently showing blanks.
 */
data class DiagnosticsReport(
    val androidRelease: String,
    val apiLevel: Int,
    val deviceModel: String,
    val internalWifiChipset: String,
    val root: RootResult,
    val hasUsbHost: Boolean,
    val usbDevices: List<IdentifiedAdapter>,
    val interfaces: List<InterfaceInfo>,
    val tools: List<ToolInfo>,
    val capability: CapabilityAssessment,
    val errors: List<String>,
) {
    /** The first recognized adapter, if any (e.g. the AR9271). */
    val recognizedAdapter: IdentifiedAdapter? get() = usbDevices.firstOrNull { it.isRecognized }
}
