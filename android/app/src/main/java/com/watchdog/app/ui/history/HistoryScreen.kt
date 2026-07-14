package com.watchdog.app.ui.history

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.unit.dp
import com.watchdog.app.data.room.ScanEntity
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun HistoryScreen(
    scans: List<ScanEntity>,
    onOpen: (Long) -> Unit,
    onDelete: (Long) -> Unit,
    onExport: (Long) -> Unit,
    onBack: () -> Unit,
) {
    var confirmDeleteId by remember { mutableStateOf<Long?>(null) }
    confirmDeleteId?.let { id ->
        AlertDialog(
            onDismissRequest = { confirmDeleteId = null },
            title = { Text("Delete scan?") },
            text = { Text("This permanently removes the scan and its devices/findings.") },
            confirmButton = { TextButton(onClick = { onDelete(id); confirmDeleteId = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { confirmDeleteId = null }) { Text("Cancel") } },
        )
    }
    ScreenChrome(title = "History", subtitle = "${scans.size} scans", onBack = onBack, primaryLabel = null) {
        if (scans.isEmpty()) {
            Text(
                "No past scans yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(scans, key = { it.id }) { s ->
                Row(
                    Modifier.fillMaxWidth().height(64.dp).clickable { onOpen(s.id) },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("${s.networkId} · ${s.status}", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            "depth ${s.depth}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = { onExport(s.id) }) { Text("Export") }
                    TextButton(onClick = { confirmDeleteId = s.id }) { Text("Delete") }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}
