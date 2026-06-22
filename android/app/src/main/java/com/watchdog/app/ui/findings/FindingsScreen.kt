package com.watchdog.app.ui.findings

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.Severity as SeverityEnum
import com.watchdog.app.service.ScanRunState
import com.watchdog.app.ui.common.ScreenChrome
import com.watchdog.app.ui.theme.Severity as SeverityColors

@Composable
fun FindingsScreen(state: ScanRunState, onRestart: () -> Unit) {
    val active = state.findings
        .filter { !it.suppressed }
        .sortedWith(
            compareByDescending<Finding> { it.priority }
                .thenByDescending { it.severity.ordinal }
                .thenByDescending { it.confidence },
        )
    val subtitle = when {
        state.cancelled -> "Scan cancelled"
        state.failureMessage != null -> "Scan failed"
        else -> "${active.size} finding${if (active.size == 1) "" else "s"} · ${state.discoveredHosts.size} host${if (state.discoveredHosts.size == 1) "" else "s"} · ${state.services.size} services"
    }
    ScreenChrome(
        title = "Findings",
        subtitle = subtitle,
        onBack = null,
        primaryLabel = "Start over",
        onPrimary = onRestart,
    ) {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            state.failureMessage?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = SeverityColors.Critical)
                Spacer(Modifier.height(12.dp))
            }

            if (active.isEmpty() && state.failureMessage == null) {
                Text(
                    "No vulnerabilities matched. Either the services are current, or (for non-distro products) the direct OSV lookup couldn't assess the version — try own-server mode in Settings for deeper matching.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            active.forEach { f ->
                FindingRow(f)
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }

            if (state.suppressed.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text(
                    "${state.suppressed.size} finding${if (state.suppressed.size == 1) "" else "s"} suppressed — patched by distro backport",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun FindingRow(f: Finding) {
    val color = when (f.severity) {
        SeverityEnum.CRITICAL -> SeverityColors.Critical
        SeverityEnum.HIGH -> SeverityColors.High
        SeverityEnum.MEDIUM -> SeverityColors.Medium
        else -> SeverityColors.Low
    }
    Column(Modifier.fillMaxWidth().padding(vertical = 14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(color))
            Spacer(Modifier.padding(4.dp))
            Text(f.severity.name, color = color, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.weight(1f))
            StateBadge(f.state.name)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "${f.product.product}${f.product.version?.let { " $it" } ?: ""}  ·  ${f.host}:${f.port}",
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(2.dp))
        Text(f.cveId, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        val meta = buildList {
            f.cvssScore?.let { add("CVSS $it") }
            add("${f.confidence}% conf")
            if (f.knownExploited) add("KEV")
            f.epss?.let { add("EPSS ${(it * 100).toInt()}%") }
        }.joinToString("  ·  ")
        Text(meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (f.why.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text(f.why.first(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun StateBadge(state: String) {
    Box(
        Modifier.clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(state, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
