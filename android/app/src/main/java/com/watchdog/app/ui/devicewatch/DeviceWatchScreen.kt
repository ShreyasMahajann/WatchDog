package com.watchdog.app.ui.devicewatch

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.devicewatch.data.WatchedDeviceEntity
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

/**
 * Device Watch home: shows the inventory for the current network and a "Scan now" sweep. Unknown
 * (untrusted, present) devices are surfaced first with a NEW badge and an inline Trust action; known
 * devices follow; devices no longer seen are listed dimmed under Offline.
 */
@Composable
fun DeviceWatchScreen(
    appVersion: String,
    network: NetworkInfo?,
    devices: List<WatchedDeviceEntity>,
    scanning: Boolean,
    onScanNow: () -> Unit,
    onOpenDevice: (Long) -> Unit,
    onTrust: (Long) -> Unit,
    onBack: () -> Unit,
) {
    val onLan = network?.cidr != null
    val unknown = devices.filter { it.present && !it.trusted }
    val known = devices.filter { it.present && it.trusted }
    val offline = devices.filter { !it.present }

    ScreenChrome(
        title = "Device Watch",
        subtitle = "Who's on your network",
        onBack = onBack,
        primaryLabel = if (scanning) "Scanning…" else "Scan now",
        primaryEnabled = onLan && !scanning,
        onPrimary = onScanNow,
        footnote = "watchDog v$appVersion",
    ) {
        InfoBanner(
            if (onLan) {
                "Watching ${network?.ssid ?: "this network"}. Devices are tracked by IP — a device that " +
                    "changes address may reappear as new."
            } else {
                "Join a Wi-Fi network to watch it."
            },
        )
        Spacer(Modifier.height(16.dp))

        if (devices.isEmpty()) {
            Text(
                if (onLan) {
                    "No devices tracked yet. Tap Scan now to sweep this network and build a baseline."
                } else {
                    "Connect to Wi-Fi, then Scan now to see who's on the network."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (unknown.isNotEmpty()) {
                    item { SectionHeader("Unknown / new (${unknown.size})") }
                    items(unknown, key = { it.id }) { d ->
                        DeviceRow(d, onClick = { onOpenDevice(d.id) }, onTrust = { onTrust(d.id) })
                    }
                }
                if (known.isNotEmpty()) {
                    item { SectionHeader("Known (${known.size})") }
                    items(known, key = { it.id }) { d ->
                        DeviceRow(d, onClick = { onOpenDevice(d.id) }, onTrust = null)
                    }
                }
                if (offline.isNotEmpty()) {
                    item { SectionHeader("Offline (${offline.size})") }
                    items(offline, key = { it.id }) { d ->
                        DeviceRow(d, onClick = { onOpenDevice(d.id) }, onTrust = null)
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun DeviceRow(
    device: WatchedDeviceEntity,
    onClick: () -> Unit,
    onTrust: (() -> Unit)?,
) {
    val primary = device.label ?: device.hostname ?: device.ip
    val secondary = buildString {
        append(device.ip)
        if (device.label != null && device.hostname != null) append(" · ${device.hostname}")
        if (device.serviceHints.isNotBlank()) append(" · ${device.serviceHints}")
    }
    Row(
        modifier = Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .then(if (device.present) Modifier else Modifier.alpha(0.55f))
            .clickable(onClick = onClick)
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(primary, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                if (device.present && !device.trusted) {
                    Text(
                        "  NEW",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                secondary,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (onTrust != null) {
            TextButton(onClick = onTrust) { Text("Trust") }
        } else {
            Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
