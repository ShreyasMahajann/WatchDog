package com.watchdog.app.ui.hosts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.ui.common.CancelConfirmDialog
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun HostsScreen(
    hosts: List<DiscoveredHost>,
    discovering: Boolean,
    onSelect: ((String) -> Unit)?,
    onBack: () -> Unit,
    onCancel: (() -> Unit)? = null,
    onStop: (() -> Unit)? = null,
) {
    var confirmCancel by remember { mutableStateOf(false) }
    if (confirmCancel && onCancel != null) {
        CancelConfirmDialog(
            onConfirm = { confirmCancel = false; onCancel?.invoke() },
            onDismiss = { confirmCancel = false },
        )
    }
    ScreenChrome(
        title = if (discovering) "Discovering hosts" else "Pick a host",
        subtitle = if (discovering) "${hosts.size} found so far…" else "${hosts.size} live host${if (hosts.size == 1) "" else "s"} — tap one to deep-scan",
        onBack = onBack,
        primaryLabel = if (onStop != null) "Continue (${hosts.size} found)" else null,
        primaryEnabled = hosts.isNotEmpty(),
        onPrimary = onStop,
        secondaryLabel = if (onCancel != null) "Cancel" else null,
        onSecondary = if (onCancel != null) ({ confirmCancel = true }) else null,
    ) {
        Column(Modifier.fillMaxSize()) {
            if (discovering) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.height(16.dp).width(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Probing the subnet…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(Modifier.height(12.dp))
            }
            LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                items(hosts, key = { it.ip }) { host ->
                    Row(
                        modifier = Modifier.fillMaxWidth().height(56.dp)
                            .then(if (onSelect != null) Modifier.clickable { onSelect(host.ip) } else Modifier),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(host.ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                            val label = host.hostname ?: host.serviceHints.firstOrNull()
                            if (label != null) {
                                Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                        Text(host.source, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (onSelect != null) {
                            Spacer(Modifier.width(8.dp))
                            Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}
