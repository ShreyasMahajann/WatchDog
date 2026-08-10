package com.watchdog.app.ui.wpa

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
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome
import com.watchdog.app.wpa.data.CaptureEntity
import com.watchdog.app.wpa.data.SubmissionStatus

/**
 * The capture library / history. Every row is a real stored capture; the status comes from the
 * local DB (updated from WPA-sec responses). Refresh polls WPA-sec for outstanding submissions —
 * it never re-uploads.
 */
@Composable
fun WpaCapturesScreen(
    captures: List<CaptureEntity>,
    busy: Boolean,
    onOpen: (Long) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "Handshakes",
        subtitle = "${captures.size} capture(s)",
        onBack = onBack,
        primaryLabel = if (busy) "Working…" else "Refresh results",
        primaryEnabled = !busy,
        onPrimary = onRefresh,
    ) {
        if (captures.isEmpty()) {
            InfoBanner("No captures yet. Import a .pcap/.cap from the hub, or capture one if your device supports monitor mode.")
            return@ScreenChrome
        }
        LazyColumn(Modifier.fillMaxWidth()) {
            items(captures, key = { it.id }) { cap ->
                CaptureRow(cap, onClick = { onOpen(cap.id) })
                Spacer(Modifier.height(10.dp))
            }
        }
    }
}

@Composable
private fun CaptureRow(cap: CaptureEntity, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onClick)
            .padding(14.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(
                cap.ssid ?: cap.bssidDisplay.ifBlank { "(unknown network)" },
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            Text(
                WpaFormat.statusLabel(cap.statusEnum),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = statusColor(cap.statusEnum),
            )
        }
        Spacer(Modifier.height(2.dp))
        val hs = if (cap.hasValidHandshake) "valid handshake ✓" else "no valid handshake"
        Text(
            "${cap.bssidDisplay.ifBlank { "—" }} · ${cap.security} · $hs",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (cap.statusEnum == SubmissionStatus.CRACKED && cap.password != null) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Password: ${cap.password}",
                style = MaterialTheme.typography.bodyMedium,
                color = androidx.compose.ui.graphics.Color(0xFF2E9E4F),
            )
        }
    }
}
