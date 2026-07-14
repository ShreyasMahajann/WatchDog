package com.watchdog.app.ui.results

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.correlate.CorrelationTarget
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.ui.ScanViewModel
import com.watchdog.app.ui.common.FindingRow
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun DeviceDetailScreen(
    host: String,
    observations: List<ServiceObservation>,
    findings: List<Finding>,
    vulnState: ScanViewModel.VulnCheckState,
    targets: List<CorrelationTarget>,
    onCheck: (CorrelationTarget) -> Unit,
    onDeepRescan: () -> Unit,
    onShare: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(title = host, subtitle = "${observations.size} services", onBack = onBack, primaryLabel = null) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
            observations.forEach { o ->
                Text(
                    "${o.port}/${o.proto}  ${o.serviceName ?: ""}  ${o.product?.let { "${it.product} ${it.version ?: ""}" } ?: ""}".trim(),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                )
                val e = o.evidence
                e?.banner?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                e?.httpServer?.let { Text("Server: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                e?.tlsSubject?.let { Text("TLS: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }

            Spacer(Modifier.height(16.dp))
            Text("Vulnerability check", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            Row {
                targets.forEach { t ->
                    val label = if (t == CorrelationTarget.OSV) "Check against OSV" else "Check against my server"
                    Button(
                        onClick = { onCheck(t) },
                        enabled = vulnState !is ScanViewModel.VulnCheckState.Running,
                    ) { Text(label) }
                    Spacer(Modifier.width(8.dp))
                }
            }
            when (vulnState) {
                is ScanViewModel.VulnCheckState.Running -> {
                    Spacer(Modifier.height(8.dp))
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                is ScanViewModel.VulnCheckState.Error -> {
                    Spacer(Modifier.height(8.dp))
                    InfoBanner(vulnState.message)
                }
                else -> {}
            }

            if (findings.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                findings.forEach { FindingRow(it); HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant) }
            } else if (vulnState is ScanViewModel.VulnCheckState.Idle) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "No vulnerabilities checked yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(20.dp))
            TextButton(onClick = onDeepRescan) { Text("Deep re-scan this device") }
            TextButton(onClick = onShare) { Text("Share device info") }
        }
    }
}
