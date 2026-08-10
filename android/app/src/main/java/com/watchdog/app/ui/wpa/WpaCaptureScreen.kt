package com.watchdog.app.ui.wpa

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

/**
 * On-device capture configuration. Only reachable when the capability model says capture is
 * possible. It runs the real root capture engine — no simulated capture. Interfaces are the ones
 * actually reported by the device.
 */
@Composable
fun WpaCaptureScreen(
    interfaces: List<String>,
    busy: Boolean,
    onStart: (iface: String, channel: Int?, durationSec: Int) -> Unit,
    onBack: () -> Unit,
) {
    var selectedIface by remember(interfaces) { mutableStateOf(interfaces.firstOrNull().orEmpty()) }
    var channel by remember { mutableStateOf("") }
    var duration by remember { mutableStateOf(60) }

    ScreenChrome(
        title = "Capture handshake",
        subtitle = "Monitor-mode capture via root",
        onBack = onBack,
        primaryLabel = if (busy) "Capturing…" else "Start capture",
        primaryEnabled = !busy && selectedIface.isNotBlank(),
        onPrimary = { onStart(selectedIface, channel.toIntOrNull(), duration) },
    ) {
        Column(Modifier.fillMaxWidth()) {
            InfoBanner("This enables monitor mode on the chosen interface and runs tcpdump as root, then validates the pcap. Only capture networks you're authorized to test.")
            Spacer(Modifier.height(16.dp))

            Label("Interface")
            if (interfaces.isEmpty()) {
                Text("No candidate interfaces detected.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                interfaces.forEach { iface ->
                    SelectRow(iface, selected = iface == selectedIface, modifier = Modifier.fillMaxWidth()) { selectedIface = iface }
                    Spacer(Modifier.height(6.dp))
                }
            }

            Spacer(Modifier.height(12.dp))
            Label("Channel (optional)")
            OutlinedTextField(
                value = channel,
                onValueChange = { channel = it.filter(Char::isDigit).take(3) },
                label = { Text("e.g. 6") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(12.dp))
            Label("Duration")
            Row(Modifier.fillMaxWidth()) {
                val options = listOf(30, 60, 120)
                options.forEachIndexed { i, sec ->
                    SelectRow("${sec}s", selected = sec == duration, modifier = Modifier.weight(1f)) { duration = sec }
                    if (i < options.lastIndex) Spacer(Modifier.width(8.dp))
                }
            }
        }
    }
}

@Composable
private fun Label(text: String) {
    Text(text.uppercase(), style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
    Spacer(Modifier.height(6.dp))
}

@Composable
private fun SelectRow(text: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val bg = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(bg)
            .clickable(onClick = onClick)
            .padding(14.dp),
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
    }
}
