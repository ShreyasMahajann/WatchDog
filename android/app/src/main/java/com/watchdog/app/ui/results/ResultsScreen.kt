package com.watchdog.app.ui.results

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.watchdog.app.data.room.HostEntity
import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.ui.common.LabeledCard
import com.watchdog.app.ui.common.RenameScanDialog
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun ResultsScreen(
    scanNetwork: String?,
    scanName: String?,
    hosts: List<HostEntity>,
    observations: List<ServiceObservation>,
    onOpenDevice: (String) -> Unit,
    onRename: (String) -> Unit,
    onShare: () -> Unit,
    onDone: () -> Unit,
) {
    val byHost = observations.groupBy { it.host }
    val sortedHosts = hosts.sortedBy { runCatching { Cidr.ipToLong(it.ip) }.getOrDefault(Long.MAX_VALUE) }
    var showRename by remember { mutableStateOf(false) }
    if (showRename) {
        RenameScanDialog(
            initial = scanName,
            onConfirm = { onRename(it); showRename = false },
            onDismiss = { showRename = false },
        )
    }
    ScreenChrome(
        title = scanName ?: "Results",
        subtitle = scanNetwork,
        onBack = null,
        primaryLabel = "Done",
        onPrimary = onDone,
        secondaryLabel = "Share report",
        onSecondary = onShare,
    ) {
        Column(Modifier.fillMaxSize()) {
            TextButton(onClick = { showRename = true }) {
                Text(if (scanName == null) "Name this scan" else "Rename scan")
            }
            Spacer(Modifier.height(4.dp))
            LabeledCard(
                label = "Summary",
                value = "${hosts.size} devices · ${observations.size} services",
            )
            Spacer(Modifier.height(12.dp))
            LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                items(sortedHosts, key = { it.id }) { h ->
                    val services = byHost[h.ip].orEmpty()
                    Row(
                        Modifier.fillMaxWidth().height(60.dp).clickable { onOpenDevice(h.ip) },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(h.ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                h.hostname ?: "${services.size} service${if (services.size == 1) "" else "s"}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}
