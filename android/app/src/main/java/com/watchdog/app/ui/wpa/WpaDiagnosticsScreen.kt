package com.watchdog.app.ui.wpa

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.ui.common.ScreenChrome
import com.watchdog.app.wpa.device.Capability
import com.watchdog.app.wpa.device.CapabilityAssessment
import com.watchdog.app.wpa.device.IdentifiedAdapter
import com.watchdog.app.wpa.device.RootStatus
import com.watchdog.app.wpa.diagnostics.DiagnosticsReport

/**
 * Renders the live diagnostics report. Everything shown comes from a real probe; capability
 * badges are colour-coded (green = confirmed, red = confirmed impossible with reason, amber =
 * can't tell from the app). No value here is a simulated "supported" state.
 */
@Composable
fun WpaDiagnosticsScreen(
    report: DiagnosticsReport?,
    loading: Boolean,
    onRefresh: () -> Unit,
    onTestRoot: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "Diagnostics",
        subtitle = "What this device actually reports",
        onBack = onBack,
        primaryLabel = if (loading) "Probing…" else "Refresh",
        primaryEnabled = !loading,
        onPrimary = onRefresh,
        secondaryLabel = "Test root access",
        onSecondary = onTestRoot,
    ) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
            if (report == null) {
                Text(
                    if (loading) "Running probes…" else "No report yet.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                return@Column
            }

            Section("System") {
                KeyValue("Android", "${report.androidRelease} (API ${report.apiLevel})")
                KeyValue("Device", report.deviceModel)
                KeyValue("Internal Wi-Fi", report.internalWifiChipset)
            }

            Section("Root") {
                KeyValue("Status", rootLabel(report.root.status))
                Note(report.root.detail)
                report.root.suPath?.let { KeyValue("su path", it) }
            }

            Section("USB / OTG") {
                KeyValue("USB host support", if (report.hasUsbHost) "Yes" else "No")
                if (report.usbDevices.isEmpty()) {
                    Note("No USB devices connected. Plug the adapter in via OTG — this screen updates automatically.")
                } else {
                    report.usbDevices.forEach { AdapterCard(it) }
                }
            }

            Section("Capture capability") {
                CapabilityRow("Monitor mode supported", report.capability.monitorModeSupported)
                CapabilityRow("Monitor mode enactable", report.capability.monitorModeEnactable)
                CapabilityRow("Packet capture", report.capability.packetCapturePossible)
                CapabilityRow("Handshake capture", report.capability.handshakeCapturePossible)
            }

            Section("Network interfaces") {
                if (report.interfaces.isEmpty()) {
                    Note("None reported.")
                } else {
                    report.interfaces.forEach { iface ->
                        val flags = buildList {
                            if (iface.isUp) add("up")
                            if (iface.looksMonitor) add("monitor")
                        }.joinToString(", ").ifEmpty { "down" }
                        KeyValue(iface.name, flags)
                    }
                }
            }

            Section("Capture tools") {
                report.tools.forEach { tool ->
                    KeyValue(tool.name, tool.path ?: "not found")
                }
            }

            if (report.errors.isNotEmpty()) {
                Section("Errors") {
                    report.errors.forEach { Note(it) }
                }
            }

            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Spacer(Modifier.height(12.dp))
    Text(
        title.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary,
    )
    Spacer(Modifier.height(6.dp))
    content()
}

@Composable
private fun KeyValue(key: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(key, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(12.dp))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f, fill = false),
        )
    }
}

@Composable
private fun Note(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 3.dp),
    )
}

@Composable
private fun CapabilityRow(name: String, capability: Capability) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(name, style = MaterialTheme.typography.bodyMedium)
            Text(
                capability.label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = capabilityColor(capability),
            )
        }
        capability.reasonOrNull?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AdapterCard(adapter: IdentifiedAdapter) {
    val d = adapter.device
    Column(
        Modifier.fillMaxWidth().padding(vertical = 6.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(14.dp),
    ) {
        val title = adapter.profile?.name ?: (d.productName ?: "Unrecognized adapter")
        Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(4.dp))
        KeyValue("VID:PID", d.idString)
        d.manufacturerName?.let { KeyValue("Vendor", it) }
        val profile = adapter.profile
        if (profile != null) {
            KeyValue("Driver", profile.driver)
            profile.firmware?.let { KeyValue("Firmware", it) }
            KeyValue("Monitor mode", yesNo(profile.monitorMode))
            KeyValue("Injection", yesNo(profile.packetInjection))
            Spacer(Modifier.height(4.dp))
            Note(profile.notes)
        } else {
            Note("Not in the known-chipset list. Its capabilities can't be confirmed — see the open contribution issues to add support.")
        }
    }
}

private fun yesNo(b: Boolean) = if (b) "Yes" else "No"

private fun rootLabel(status: RootStatus): String = when (status) {
    RootStatus.NONE -> "Not rooted"
    RootStatus.PRESENT_UNGRANTED -> "su present (not confirmed)"
    RootStatus.GRANTED -> "Rooted (granted)"
    RootStatus.UNKNOWN -> "Unknown"
}

@Composable
private fun capabilityColor(capability: Capability): Color = when (capability) {
    Capability.Supported -> Color(0xFF2E9E4F)
    is Capability.Unsupported -> MaterialTheme.colorScheme.error
    is Capability.Unknown -> Color(0xFFB8860B)
}
