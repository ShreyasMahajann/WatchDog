package com.watchdog.app.ui.devicewatch

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.watchdog.app.devicewatch.data.WatchedDeviceEntity
import com.watchdog.app.ui.common.LabeledCard
import com.watchdog.app.ui.common.ScreenChrome
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One watched device: its attributes plus rename / trust / forget actions. */
@Composable
fun DeviceWatchDetailScreen(
    device: WatchedDeviceEntity,
    onRename: (String) -> Unit,
    onTrust: () -> Unit,
    onUntrust: () -> Unit,
    onForget: () -> Unit,
    onBack: () -> Unit,
) {
    var name by rememberSaveable(device.id) { mutableStateOf(device.label ?: "") }
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }

    ScreenChrome(
        title = device.label ?: device.hostname ?: device.ip,
        subtitle = if (device.present) "Present on ${device.networkLabel}" else "Offline · last on ${device.networkLabel}",
        onBack = onBack,
        primaryLabel = null,
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { LabeledCard("IP address", device.ip) }
            item { LabeledCard("Hostname", device.hostname ?: "—") }
            item { LabeledCard("Services", device.serviceHints.ifBlank { "—" }) }
            item { LabeledCard("Status", if (device.present) "Present" else "Offline") }
            item { LabeledCard("Trust", if (device.trusted) "Trusted / known" else "Not trusted (new)") }
            item { LabeledCard("First seen", fmt.format(Date(device.firstSeen))) }
            item { LabeledCard("Last seen", fmt.format(Date(device.lastSeen))) }

            item {
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Device name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = { onRename(name) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Save name")
                }
            }

            item {
                Spacer(Modifier.height(4.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (device.trusted) {
                        OutlinedButton(onClick = onUntrust, modifier = Modifier.weight(1f)) { Text("Untrust") }
                    } else {
                        Button(onClick = onTrust, modifier = Modifier.weight(1f)) { Text("Trust") }
                    }
                    OutlinedButton(
                        onClick = onForget,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    ) { Text("Forget") }
                }
            }
        }
    }
}
