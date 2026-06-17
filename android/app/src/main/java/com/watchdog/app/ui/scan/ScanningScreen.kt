package com.watchdog.app.ui.scan

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.ScanPhase
import com.watchdog.app.service.ScanRunState
import com.watchdog.app.ui.common.LabeledCard
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun ScanningScreen(state: ScanRunState, onCancel: () -> Unit) {
    val phaseLabel = when (state.phase) {
        ScanPhase.DISCOVERING -> "Discovering hosts"
        ScanPhase.ENUMERATING -> "Scanning ports"
        ScanPhase.FINGERPRINTING -> "Fingerprinting services"
        ScanPhase.CORRELATING -> "Checking CVE database"
        ScanPhase.DONE -> "Finishing"
    }
    ScreenChrome(
        title = "Scanning",
        subtitle = "Runs in the background — you'll get a notification when it's done.",
        onBack = null,
        primaryLabel = "Cancel scan",
        onPrimary = onCancel,
    ) {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            if (state.hostsTotal > 0) {
                LinearProgressIndicator(
                    progress = { state.hostsDone.toFloat() / state.hostsTotal.coerceAtLeast(1) },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(16.dp))

            LabeledCard(label = "Phase", value = phaseLabel)
            Spacer(Modifier.height(8.dp))

            StatRow("Hosts", "${state.hostsDone} / ${state.hostsTotal.coerceAtLeast(state.discoveredHosts.size)}")
            state.currentHost?.let { StatRow("Current host", it, mono = true) }
            StatRow("Open ports", state.openPortCount.toString())
            StatRow("Services fingerprinted", state.services.size.toString())

            if (state.errors.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text("${state.errors.size} non-fatal error(s)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.fillMaxWidth().height(36.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.weight(1f))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
        )
    }
}
