package com.watchdog.app.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun SettingsScreen(
    settings: Settings,
    onSetMode: (CorrelatorMode) -> Unit,
    onSaveServer: (String, String) -> Unit,
    onSetDepth: (ScanDepth) -> Unit,
    onBack: () -> Unit,
) {
    var url by remember(settings.serverBaseUrl) { mutableStateOf(settings.serverBaseUrl) }
    var token by remember(settings.serverToken) { mutableStateOf(settings.serverToken) }

    ScreenChrome(
        title = "Settings",
        subtitle = "Where CVE correlation runs",
        onBack = onBack,
        primaryLabel = null,
    ) {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            ModeRow(
                selected = settings.correlatorMode == CorrelatorMode.DIRECT_OSV,
                title = "Direct (OSV public)",
                body = "The phone queries OSV.dev + CISA KEV + EPSS directly. No server needed.",
                onClick = { onSetMode(CorrelatorMode.DIRECT_OSV) },
            )
            ModeRow(
                selected = settings.correlatorMode == CorrelatorMode.OWN_SERVER,
                title = "Own server",
                body = "POST evidence to your own backend running the watchDog correlation engine.",
                onClick = { onSetMode(CorrelatorMode.OWN_SERVER) },
            )

            if (settings.correlatorMode == CorrelatorMode.OWN_SERVER) {
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Server base URL") },
                    placeholder = { Text("https://your-site.vercel.app") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = token,
                    onValueChange = { token = it },
                    label = { Text("Device token (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                InfoBanner("Requests go to <base URL>/api/v1/correlate with the frozen CorrelateRequest body.")
                Spacer(Modifier.height(8.dp))
                androidx.compose.material3.TextButton(onClick = { onSaveServer(url, token) }) {
                    Text("Save server")
                }
            }

            Spacer(Modifier.height(24.dp))
            Text("Default port depth", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            ScanDepth.entries.forEach { depth ->
                Row(
                    Modifier.fillMaxWidth().height(44.dp)
                        .selectable(selected = depth == settings.defaultDepth, onClick = { onSetDepth(depth) }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = depth == settings.defaultDepth, onClick = { onSetDepth(depth) })
                    Text(depth.label, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun ModeRow(selected: Boolean, title: String, body: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().selectable(selected = selected, onClick = onClick),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Column(Modifier.padding(top = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
        }
    }
}
