package com.watchdog.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsStore
import kotlinx.coroutines.launch

/** Correlator mode, own-server endpoint, and default scan depth. */
@Composable
fun SettingsScreen(store: SettingsStore, settings: Settings) {
    val scope = rememberCoroutineScope()
    var url by remember(settings.serverBaseUrl) { mutableStateOf(settings.serverBaseUrl) }
    var token by remember(settings.serverToken) { mutableStateOf(settings.serverToken) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        SectionTitle("Correlation source")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = settings.correlatorMode == CorrelatorMode.DIRECT_OSV,
                onClick = { scope.launch { store.setMode(CorrelatorMode.DIRECT_OSV) } },
                label = { Text("On-device (OSV/KEV/EPSS)") },
            )
            FilterChip(
                selected = settings.correlatorMode == CorrelatorMode.OWN_SERVER,
                onClick = { scope.launch { store.setMode(CorrelatorMode.OWN_SERVER) } },
                label = { Text("Own server") },
            )
        }
        Spacer(Modifier.height(20.dp))

        SectionTitle("Own server")
        Text(
            "POST observations to your own backend (the correlation engine). Leave blank to always use on-device OSV.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = url, onValueChange = { url = it }, singleLine = true,
            label = { Text("Server base URL") }, modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = token, onValueChange = { token = it }, singleLine = true,
            label = { Text("Token (optional)") }, modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = { scope.launch { store.setServer(url, token) } }) { Text("Save server") }
        Spacer(Modifier.height(24.dp))

        SectionTitle("Default scan depth")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ScanDepth.entries.forEach { d ->
                FilterChip(
                    selected = settings.defaultDepth == d,
                    onClick = { scope.launch { store.setDepth(d) } },
                    label = { Text(d.label) },
                )
            }
        }
    }
}
