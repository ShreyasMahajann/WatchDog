package com.watchdog.app.ui.select

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun SelectDevicesScreen(
    hosts: List<DiscoveredHost>,
    selected: Set<String>,
    onToggle: (String) -> Unit,
    onSelectAll: () -> Unit,
    onClear: () -> Unit,
    onRediscover: () -> Unit,
    onContinue: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "Select devices",
        subtitle = "${hosts.size} found · ${selected.size} selected",
        onBack = onBack,
        primaryLabel = "Choose ports (${selected.size})",
        primaryEnabled = selected.isNotEmpty(),
        onPrimary = onContinue,
    ) {
        Column(Modifier.fillMaxSize()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onSelectAll) { Text("Select all") }
                TextButton(onClick = onClear) { Text("Clear") }
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onRediscover) { Text("Discover again") }
            }
            LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                items(hosts, key = { it.ip }) { host ->
                    Row(
                        Modifier.fillMaxWidth().height(56.dp).clickable { onToggle(host.ip) },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = host.ip in selected, onCheckedChange = { onToggle(host.ip) })
                        Column(Modifier.weight(1f)) {
                            Text(host.ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                            val label = host.hostname ?: host.serviceHints.firstOrNull()
                            if (label != null) {
                                Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                        Text(host.source, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}
