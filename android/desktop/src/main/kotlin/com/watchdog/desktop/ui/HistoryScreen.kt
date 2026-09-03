package com.watchdog.desktop.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.watchdog.desktop.data.DesktopScanStore
import com.watchdog.desktop.data.ScanSummary
import com.watchdog.desktop.scan.DesktopScanController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())

/** Browse, reopen, rename, and delete saved scans. */
@Composable
fun HistoryScreen(
    controller: DesktopScanController,
    scanStore: DesktopScanStore,
    onOpened: () -> Unit,
) {
    val version by controller.historyVersion.collectAsState()
    var scans by remember { mutableStateOf<List<ScanSummary>>(emptyList()) }
    var renaming by remember { mutableStateOf<ScanSummary?>(null) }

    LaunchedEffect(version) {
        scans = withContext(Dispatchers.IO) { scanStore.listScans() }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        SectionTitle("Scan history (${scans.size})")
        if (scans.isEmpty()) {
            Text("No saved scans yet. Run a scan from NetScan.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        scans.forEach { s ->
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Text(s.label, style = MaterialTheme.typography.titleSmall)
                Text(
                    "${dateFmt.format(Date(s.startedAt))} · ${s.cidr ?: s.networkId} · depth ${s.depth}",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(onClick = {
                        val record = scanStore.getScan(s.id)
                        if (record != null) { controller.openHistory(record); onOpened() }
                    }) { Text("Open") }
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = { renaming = s }) { Text("Rename") }
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = { controller.deleteScan(s.id) }) { Text("Delete") }
                }
                HorizontalDivider(Modifier.padding(top = 8.dp))
            }
        }
    }

    renaming?.let { target ->
        var text by remember(target.id) { mutableStateOf(target.name ?: "") }
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text("Name scan") },
            text = {
                OutlinedTextField(
                    value = text, onValueChange = { text = it },
                    label = { Text("Scan name") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = { TextButton(onClick = { controller.renameScan(target.id, text); renaming = null }) { Text("Save") } },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } },
        )
    }
}
