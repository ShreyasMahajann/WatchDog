package com.watchdog.app.ui.history

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import com.watchdog.app.ui.common.RenameScanDialog
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun HistoryScreen(
    scans: List<ScanEntity>,
    onOpen: (Long) -> Unit,
    onRename: (Long, String) -> Unit,
    onDelete: (Long) -> Unit,
    onExport: (Long) -> Unit,
    onBack: () -> Unit,
) {
    var confirmDeleteId by remember { mutableStateOf<Long?>(null) }
    var renameTarget by remember { mutableStateOf<ScanEntity?>(null) }
    var query by remember { mutableStateOf("") }

    confirmDeleteId?.let { id ->
        AlertDialog(
            onDismissRequest = { confirmDeleteId = null },
            title = { Text("Delete scan?") },
            text = { Text("This permanently removes the scan and its devices/findings.") },
            confirmButton = { TextButton(onClick = { onDelete(id); confirmDeleteId = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { confirmDeleteId = null }) { Text("Cancel") } },
        )
    }
    renameTarget?.let { scan ->
        RenameScanDialog(
            initial = scan.name,
            onConfirm = { name -> onRename(scan.id, name); renameTarget = null },
            onDismiss = { renameTarget = null },
        )
    }

    val filtered = scans.filter { s ->
        query.isBlank() || listOfNotNull(s.name, s.networkId, s.status)
            .any { it.contains(query, ignoreCase = true) }
    }

    ScreenChrome(title = "History", subtitle = "${scans.size} scans", onBack = onBack, primaryLabel = null) {
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("Search scans") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        if (filtered.isEmpty()) {
            Text(
                if (scans.isEmpty()) "No past scans yet." else "No scans match \"$query\".",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(filtered, key = { it.id }) { s ->
                Row(
                    Modifier.fillMaxWidth().height(64.dp).clickable { onOpen(s.id) },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(s.name ?: "${s.networkId} · ${s.status}", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            "depth ${s.depth}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = { renameTarget = s }) { Text("Rename") }
                    TextButton(onClick = { onExport(s.id) }) { Text("Export") }
                    TextButton(onClick = { confirmDeleteId = s.id }) { Text("Delete") }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}
