package com.watchdog.app.ui.wpa

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.ui.common.ScreenChrome
import com.watchdog.app.wpa.data.CaptureEntity
import com.watchdog.app.wpa.data.SubmissionStatus

/**
 * Full detail + history for one capture. Submission is explicit and confirmed; an already-submitted
 * or cracked capture can't be re-uploaded. Everything shown is real DB/WPA-sec state.
 */
@Composable
fun WpaCaptureDetailScreen(
    capture: CaptureEntity,
    busy: Boolean,
    onSubmit: () -> Unit,
    onRefresh: () -> Unit,
    onDelete: () -> Unit,
    onBack: () -> Unit,
) {
    var confirmSubmit by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }

    val status = capture.statusEnum
    val submittable = status == SubmissionStatus.NOT_SUBMITTED || status == SubmissionStatus.FAILED
    val primaryLabel = when {
        busy -> "Working…"
        submittable -> "Submit to WPA-sec"
        status == SubmissionStatus.CRACKED -> "Refresh"
        else -> "Refresh result"
    }

    ScreenChrome(
        title = capture.ssid ?: "Capture",
        subtitle = capture.bssidDisplay.ifBlank { "unknown BSSID" },
        onBack = onBack,
        primaryLabel = primaryLabel,
        primaryEnabled = !busy,
        onPrimary = { if (submittable) confirmSubmit = true else onRefresh() },
        secondaryLabel = "Delete capture",
        onSecondary = { confirmDelete = true },
    ) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
            StatusCard(capture)
            Section("Network") {
                Kv("SSID", capture.ssid ?: "(hidden / unknown)")
                Kv("BSSID", capture.bssidDisplay.ifBlank { "—" })
                Kv("Channel", capture.channel?.toString() ?: "—")
                Kv("Security", capture.security)
            }
            Section("Handshake") {
                Kv("Valid handshake", if (capture.hasValidHandshake) "Yes ✓" else "No")
                Kv("PMKID present", if (capture.hasPmkid) "Yes" else "No")
                Kv("EAPOL packets", capture.eapolCount.toString())
            }
            Section("File") {
                Kv("Name", capture.fileName)
                Kv("Size", WpaFormat.size(capture.sizeBytes))
                Kv("MD5", capture.md5)
                Kv("Source", capture.source)
                Kv("Captured/added", WpaFormat.time(capture.capturedAt))
            }
            Section("Submission") {
                Kv("Status", WpaFormat.statusLabel(status))
                capture.statusDetail?.let { Kv("Detail", it) }
                Kv("Submitted", WpaFormat.time(capture.submittedAt))
                Kv("Last checked", WpaFormat.time(capture.lastCheckedAt))
            }
            Spacer(Modifier.height(8.dp))
        }
    }

    if (confirmSubmit) {
        AlertDialog(
            onDismissRequest = { confirmSubmit = false },
            title = { Text("Submit to WPA-sec?") },
            text = { Text("This uploads the capture file to wpa-sec.stanev.org for cracking. Only do this for networks you're authorized to test.") },
            confirmButton = { TextButton(onClick = { confirmSubmit = false; onSubmit() }) { Text("Submit") } },
            dismissButton = { TextButton(onClick = { confirmSubmit = false }) { Text("Cancel") } },
        )
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete capture?") },
            text = { Text("Removes the file and its history from this device. WPA-sec is not affected.") },
            confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun StatusCard(capture: CaptureEntity) {
    val status = capture.statusEnum
    Column(
        Modifier.fillMaxWidth().padding(bottom = 4.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(16.dp),
    ) {
        Text(WpaFormat.statusLabel(status), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = statusColor(status))
        if (status == SubmissionStatus.CRACKED && capture.password != null) {
            Spacer(Modifier.height(6.dp))
            Text("Password", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(capture.password, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace, color = Color(0xFF2E9E4F))
        } else if (status == SubmissionStatus.SUBMITTED) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Awaiting a result. WPA-sec doesn't report a per-file queue position — Refresh checks whether it's cracked yet.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Spacer(Modifier.height(12.dp))
    Text(title.uppercase(), style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
    Spacer(Modifier.height(6.dp))
    content()
}

@Composable
private fun Kv(key: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(key, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(0.dp))
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f, fill = false))
    }
}
