package com.watchdog.app.ui.wpa

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.ui.common.ScreenChrome

/**
 * WPA Handshake landing menu. Import, Handshakes and the WPA-sec key work on any phone. Capture is
 * gated on the live capability model — enabled only when the device can actually do monitor mode.
 */
@Composable
fun WpaHubScreen(
    appVersion: String,
    captureCount: Int,
    keyConfigured: Boolean,
    captureSupported: Boolean,
    onOpenDiagnostics: () -> Unit,
    onImport: () -> Unit,
    onStartCapture: () -> Unit,
    onOpenCaptures: () -> Unit,
    onOpenKey: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "WPA Handshake",
        subtitle = "Capture, validate & crack via WPA-sec",
        onBack = onBack,
        primaryLabel = null,
        footnote = "watchDog v$appVersion",
    ) {
        WpaMenuCard("Diagnostics", "What this phone & adapter can actually do", enabled = true, onClick = onOpenDiagnostics)
        Spacer(Modifier.height(12.dp))
        WpaMenuCard("Import handshake", "Add a .pcap/.cap captured elsewhere", enabled = true, onClick = onImport)
        Spacer(Modifier.height(12.dp))
        WpaMenuCard(
            title = "Capture handshake",
            subtitle = if (captureSupported) "Monitor mode available on this device" else "Needs root + a supported adapter",
            enabled = captureSupported,
            onClick = onStartCapture,
        )
        Spacer(Modifier.height(12.dp))
        WpaMenuCard("Handshakes", "Captures, submission & results ($captureCount)", enabled = true, onClick = onOpenCaptures)
        Spacer(Modifier.height(12.dp))
        WpaMenuCard(
            title = "WPA-sec key",
            subtitle = if (keyConfigured) "Configured ✓" else "Not set — tap to add",
            enabled = true,
            onClick = onOpenKey,
        )
    }
}

@Composable
internal fun WpaMenuCard(title: String, subtitle: String, enabled: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier.alpha(0.5f))
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (enabled) {
            Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
