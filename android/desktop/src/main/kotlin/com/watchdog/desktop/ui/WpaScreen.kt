package com.watchdog.desktop.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.wpa.data.Capture
import com.watchdog.app.wpa.data.SubmissionStatus
import com.watchdog.app.wpa.tracking.RefreshOutcome
import com.watchdog.app.wpa.tracking.SubmitOutcome
import com.watchdog.app.wpa.tracking.WpaSubmissionService
import com.watchdog.desktop.data.DesktopSecretStore
import com.watchdog.desktop.data.DesktopWpaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.swing.JFileChooser

/**
 * Desktop WPA Handshake tool: import a capture, set the WPA-sec key, submit, and
 * track cracked results. Analysis, the WPA-sec client, and the submit/track logic
 * are the same core code the Android app uses. Live capture is Android-only.
 */
@Composable
fun WpaScreen() {
    val scope = rememberCoroutineScope()
    val store = remember { DesktopWpaStore() }
    val secrets = remember { DesktopSecretStore() }
    val service = remember { WpaSubmissionService(store, secrets) }

    var captures by remember { mutableStateOf<List<Capture>>(emptyList()) }
    var keyConfigured by remember { mutableStateOf(secrets.isConfigured()) }
    var keyInput by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun reload() { captures = store.listAll() }
    remember { reload(); true }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("WPA Handshake", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        Text("Import a capture, submit to WPA-sec, and track cracked results.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(16.dp))

        SectionTitle("WPA-sec key ${if (keyConfigured) "· configured" else "· not set"}")
        Text(
            "Stored locally in a key file (not encrypted at rest — desktop personal use).",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = keyInput, onValueChange = { keyInput = it }, singleLine = true,
                label = { Text("32-hex WPA-sec key") }, modifier = Modifier.weight(1f),
            )
            Button(onClick = {
                val k = keyInput.trim()
                if (k.isEmpty()) { message = "Key was empty — nothing saved." } else {
                    secrets.setKey(k); keyConfigured = true; keyInput = ""
                    message = if (DesktopSecretStore.looksValid(k)) "WPA-sec key saved."
                    else "Key saved, but it doesn't look like a 32-hex key — double-check it."
                }
            }) { Text("Save") }
            OutlinedButton(onClick = { secrets.clear(); keyConfigured = false; message = "WPA-sec key removed." }) { Text("Clear") }
        }
        Spacer(Modifier.height(20.dp))

        SectionTitle("Captures (${captures.size})")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !busy, onClick = {
                val file = pickCaptureFile()
                if (file != null) {
                    scope.launch {
                        busy = true
                        val bytes = withContext(Dispatchers.IO) { runCatching { file.readBytes() }.getOrNull() }
                        message = if (bytes == null) "Could not read the file." else {
                            when (val r = withContext(Dispatchers.IO) { store.importBytes(bytes, file.name) }) {
                                is DesktopWpaStore.ImportResult.Ok ->
                                    if (r.alreadyExisted) "Already imported: ${r.capture.fileName}"
                                    else if (r.capture.hasValidHandshake) "Imported ${r.capture.ssid ?: r.capture.bssidDisplay} — valid handshake ✓"
                                    else "Imported ${r.capture.fileName}, but no valid WPA handshake found."
                                is DesktopWpaStore.ImportResult.Failed -> "Import failed: ${r.reason}"
                            }
                        }
                        reload(); busy = false
                    }
                }
            }) { Text("Import capture") }
            OutlinedButton(enabled = !busy, onClick = {
                scope.launch {
                    busy = true
                    message = when (val r = service.refresh()) {
                        is RefreshOutcome.Updated ->
                            if (r.newlyCracked > 0) "${r.newlyCracked} password(s) found!" else "Checked ${r.checked} submission(s) — no new results."
                        RefreshOutcome.NoKey -> "Set your WPA-sec key first."
                        RefreshOutcome.InvalidKey -> "WPA-sec rejected the key."
                        is RefreshOutcome.NetworkError -> "Couldn't reach WPA-sec: ${r.detail}"
                    }
                    reload(); busy = false
                }
            }) { Text("Refresh results") }
        }
        message?.let { Spacer(Modifier.height(8.dp)); Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        Spacer(Modifier.height(12.dp))

        if (captures.isEmpty()) {
            Text("No captures yet. Import a .pcap/.cap/.pcapng handshake.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        captures.forEach { cap ->
            CaptureRow(
                capture = cap,
                busy = busy,
                onSubmit = {
                    scope.launch {
                        busy = true
                        message = when (val r = service.submit(cap.id)) {
                            SubmitOutcome.Submitted -> "Submitted to WPA-sec. Use Refresh to check for a result."
                            SubmitOutcome.NoKey -> "Set your WPA-sec key first."
                            SubmitOutcome.AlreadySubmitted -> "Already submitted — not re-uploading."
                            SubmitOutcome.NotFound -> "Capture not found."
                            is SubmitOutcome.Failed -> "Submit failed: ${r.detail}"
                        }
                        reload(); busy = false
                    }
                },
                onDelete = { store.delete(cap); reload() },
            )
        }
    }
}

@Composable
private fun CaptureRow(capture: Capture, busy: Boolean, onSubmit: () -> Unit, onDelete: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 6.dp).clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant).padding(12.dp),
    ) {
        Text(capture.ssid ?: capture.bssidDisplay.ifBlank { capture.fileName }, fontWeight = FontWeight.Medium)
        Text(
            "${capture.bssidDisplay}  ·  ${if (capture.hasValidHandshake) "valid handshake ✓" else "no handshake"}  ·  ${capture.statusEnum}",
            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (capture.statusEnum == SubmissionStatus.CRACKED && capture.password != null) {
            Text("Password: ${capture.password}", fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.primary)
        }
        capture.statusDetail?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                enabled = !busy && capture.hasValidHandshake && capture.statusEnum == SubmissionStatus.NOT_SUBMITTED,
                onClick = onSubmit,
            ) { Text("Submit") }
            OutlinedButton(enabled = !busy, onClick = onDelete) { Text("Delete") }
        }
    }
    HorizontalDivider()
}

/** Native file chooser (runs on the Compose/EDT thread from the click callback). */
private fun pickCaptureFile(): java.io.File? {
    val chooser = JFileChooser().apply { dialogTitle = "Import handshake capture" }
    return if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) chooser.selectedFile else null
}
