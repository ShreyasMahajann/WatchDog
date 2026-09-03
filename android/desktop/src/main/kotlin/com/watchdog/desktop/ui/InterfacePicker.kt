package com.watchdog.desktop.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.desktop.net.DesktopNetworkContext

/**
 * Adapter chooser: lets the user pick which network interface to scan on when more
 * than one is active (e.g. a laptop's Wi-Fi plus an Ethernet dock, or a second USB
 * Wi-Fi adapter). "Auto" restores the Wi-Fi-preferred auto-pick.
 */
@Composable
fun InterfacePicker(netCtx: DesktopNetworkContext, onChanged: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    // Recomputed each recomposition tick via the bump key so refreshes re-list adapters.
    var bump by remember { mutableStateOf(0) }
    val choices = remember(bump) { netCtx.interfaces() }
    val selectedId = netCtx.selectedId()
    val selectedLabel = when {
        selectedId == null -> "Auto" + (choices.firstOrNull { it.isWifi } ?: choices.firstOrNull())?.let { "  (${it.displayName.ifBlank { it.id }})" }.orEmpty()
        else -> choices.firstOrNull { it.id == selectedId }?.label ?: selectedId
    }

    Column(Modifier.fillMaxWidth()) {
        Text("Scan adapter", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = { bump++; expanded = true }) { Text(selectedLabel) }
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                DropdownMenuItem(
                    text = { Text("Auto (Wi-Fi preferred)") },
                    onClick = { netCtx.select(null); expanded = false; onChanged() },
                )
                choices.forEach { c ->
                    DropdownMenuItem(
                        text = { Text(c.label) },
                        onClick = { netCtx.select(c.id); expanded = false; onChanged() },
                    )
                }
                if (choices.isEmpty()) {
                    DropdownMenuItem(text = { Text("No active adapters found") }, onClick = { expanded = false }, enabled = false)
                }
            }
        }
    }
}
