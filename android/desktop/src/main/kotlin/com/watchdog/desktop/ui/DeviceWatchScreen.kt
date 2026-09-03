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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.devicewatch.DeviceWatchScanner
import com.watchdog.app.devicewatch.WatchOutcome
import com.watchdog.app.devicewatch.WatchScope
import com.watchdog.app.devicewatch.WatchedDevice
import com.watchdog.desktop.net.DesktopNetworkContext
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.ScanScope
import com.watchdog.app.scan.discovery.ReachabilityDiscoverer
import com.watchdog.app.scan.discovery.TcpProbeDiscoverer
import com.watchdog.desktop.data.DesktopDeviceWatchStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Desktop Device Watch: inventory the current LAN and flag new devices. */
@Composable
fun DeviceWatchScreen(netCtx: DesktopNetworkContext) {
    val scope = rememberCoroutineScope()
    val store = remember { DesktopDeviceWatchStore() }
    val engine = remember { ScanEngine(discoverers = listOf(TcpProbeDiscoverer(), ReachabilityDiscoverer())) }
    val scanner = remember { DeviceWatchScanner(netCtx, engine, store, requireWifi = false) }

    var network by remember { mutableStateOf(netCtx.current()) }
    var devices by remember { mutableStateOf<List<WatchedDevice>>(emptyList()) }
    var scanning by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    fun reload() {
        val scopeKey = network?.let { WatchScope.of(it) }
        devices = if (scopeKey == null) emptyList() else store.listScope(scopeKey)
    }

    remember { reload(); true }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Device Watch", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = { network = netCtx.current(); reload() }) { Text("Refresh") }
        }
        Text(
            network?.let { "Network: ${it.ssid ?: it.cidr?.let { c -> com.watchdog.app.net.Cidr.longToIp(c.networkAddr) + "/" + c.prefixLength } ?: "?"}" }
                ?: "No active LAN",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))
        InterfacePicker(netCtx, onChanged = { network = netCtx.current(); reload() })
        Spacer(Modifier.height(12.dp))

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                enabled = !scanning && network?.cidr != null,
                onClick = {
                    scope.launch {
                        scanning = true
                        message = when (val r = withContext(Dispatchers.Default) {
                            scanner.scan(ScanConfig(scope = ScanScope.WHOLE_NETWORK, identityProbes = false))
                        }) {
                            WatchOutcome.NoNetwork -> "No LAN to sweep. Connect and refresh."
                            is WatchOutcome.Scanned -> buildString {
                                append("${r.present} present")
                                if (r.newCount > 0) append(" · ${r.newCount} new")
                                if (r.offline > 0) append(" · ${r.offline} offline")
                            }
                        }
                        reload()
                        scanning = false
                    }
                },
            ) { Text("Scan now") }
            if (scanning) {
                CircularProgressIndicator(Modifier.height(22.dp).width(22.dp))
                Text("Sweeping…", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            message?.let { Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        Spacer(Modifier.height(16.dp))

        SectionTitle("Devices (${devices.size})")
        if (devices.isEmpty()) {
            Text("No devices yet. Run a scan to build the baseline.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        devices.forEach { d ->
            DeviceRow(
                device = d,
                onTrust = { store.setTrusted(d.id, !d.trusted); reload() },
                onForget = { store.forget(d.id); reload() },
            )
        }
    }
}

@Composable
private fun DeviceRow(device: WatchedDevice, onTrust: () -> Unit, onForget: () -> Unit) {
    val isNew = !device.trusted && device.present
    Column(
        Modifier.fillMaxWidth().padding(vertical = 6.dp).clip(RoundedCornerShape(10.dp))
            .background(if (isNew) Color(0x22D97706) else MaterialTheme.colorScheme.surfaceVariant)
            .padding(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    (device.label ?: device.hostname ?: device.ip) + if (isNew) "  • NEW" else "",
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    "${device.ip}${if (device.serviceHints.isNotBlank()) "  ·  ${device.serviceHints}" else ""}",
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    (if (device.present) "present" else "offline") + (if (device.trusted) " · trusted" else ""),
                    style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(onClick = onTrust) { Text(if (device.trusted) "Untrust" else "Trust") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = onForget) { Text("Forget") }
        }
    }
    HorizontalDivider()
}
