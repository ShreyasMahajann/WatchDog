package com.watchdog.app.ui.home

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

/** App home / tool menu. NetScan is the only active tool today; the rest are placeholders. */
@Composable
fun HomeScreen(
    appVersion: String,
    onOpenNetScan: () -> Unit,
    onOpenWpa: () -> Unit,
    onOpenDeviceWatch: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    ScreenChrome(
        title = "watchDog",
        subtitle = "Portable security toolkit",
        onBack = null,
        primaryLabel = null,
        secondaryLabel = "Settings",
        onSecondary = onOpenSettings,
        footnote = "watchDog v$appVersion",
    ) {
        ToolCard(
            title = "NetScan",
            subtitle = "Find devices & exposures on your network",
            enabled = true,
            onClick = onOpenNetScan,
        )
        Spacer(Modifier.height(12.dp))
        ToolCard(title = "Wi-Fi Audit", subtitle = "Coming soon", enabled = false, onClick = {})
        Spacer(Modifier.height(12.dp))
        ToolCard(
            title = "Device Watch",
            subtitle = "Track who's on your network",
            enabled = true,
            onClick = onOpenDeviceWatch,
        )
        Spacer(Modifier.height(12.dp))
        ToolCard(
            title = "WPA Handshake",
            subtitle = "Capture & crack via WPA-sec",
            enabled = true,
            onClick = onOpenWpa,
        )
    }
}

@Composable
private fun ToolCard(title: String, subtitle: String, enabled: Boolean, onClick: () -> Unit) {
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
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (enabled) {
            Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
