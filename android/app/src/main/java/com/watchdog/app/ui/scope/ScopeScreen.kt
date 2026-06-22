package com.watchdog.app.ui.scope

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun ScopeScreen(
    network: NetworkInfo?,
    selectedDepth: ScanDepth,
    onDepthChange: (ScanDepth) -> Unit,
    allowLarge: Boolean,
    onAllowLargeChange: (Boolean) -> Unit,
    onWholeNetwork: () -> Unit,
    onSingleHost: () -> Unit,
    onBack: () -> Unit,
) {
    val cidr = network?.cidr
    val large = cidr != null && cidr.prefixLength < Cidr.SAFE_MIN_PREFIX
    ScreenChrome(
        title = "What do you want to scan?",
        subtitle = network?.ssid?.let { "Target: $it · ${cidr?.let { c -> "${Cidr.longToIp(c.networkAddr)}/${c.prefixLength}" }}" },
        onBack = onBack,
        primaryLabel = null,
    ) {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            ChoiceCard(
                title = "Scan the whole network",
                body = "Discover every live host, then deep-scan them all automatically. Runs in the background and notifies you when done.",
                onClick = onWholeNetwork,
            )
            Spacer(Modifier.height(12.dp))
            ChoiceCard(
                title = "Scan a specific host",
                body = "Discover hosts first, pick one, then run a deep scan on just that host in the background.",
                onClick = onSingleHost,
            )

            Spacer(Modifier.height(24.dp))
            Text("Port depth", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            ScanDepth.entries.forEach { depth ->
                Row(
                    Modifier.fillMaxWidth().height(44.dp)
                        .selectable(selected = depth == selectedDepth, onClick = { onDepthChange(depth) }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = depth == selectedDepth, onClick = { onDepthChange(depth) })
                    Text(depth.label, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.weight(1f))
                    Text(depth.estimate, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            if (large) {
                Spacer(Modifier.height(16.dp))
                InfoBanner("This subnet is large (${cidr?.hostCount} addresses). Scanning it fully can take a while.")
                Row(
                    Modifier.fillMaxWidth().height(44.dp)
                        .selectable(selected = allowLarge, onClick = { onAllowLargeChange(!allowLarge) }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = allowLarge, onClick = { onAllowLargeChange(!allowLarge) })
                    Text("Scan this large subnet anyway", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun ChoiceCard(title: String, body: String, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
