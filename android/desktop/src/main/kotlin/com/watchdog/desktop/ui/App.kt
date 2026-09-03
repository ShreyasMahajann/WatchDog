package com.watchdog.desktop.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.scan.ScanScope
import com.watchdog.desktop.net.DesktopNetworkContext
import com.watchdog.desktop.scan.DesktopScanController

/**
 * The desktop NetScan flow in a single window: detect the LAN, discover hosts,
 * pick some, scan + fingerprint, then correlate on demand. Reuses the shared
 * :core engine and live state model; only the presentation is desktop-specific.
 */
@Composable
fun App() {
    val scope = rememberCoroutineScope()
    val netCtx = remember { DesktopNetworkContext() }
    val controller = remember { DesktopScanController(scope, netCtx) }

    var network by remember { mutableStateOf<NetworkInfo?>(netCtx.current()) }
    var depth by remember { mutableStateOf(ScanDepth.TOP_1000) }
    val selected = remember { mutableStateListOf<String>() }

    val state by controller.state.collectAsState()
    val vuln by controller.vuln.collectAsState()
    val busy by controller.busyMessage.collectAsState()

    val config = ScanConfig(scope = ScanScope.WHOLE_NETWORK, depth = depth, identityProbes = false)

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
    ) {
        Text("watchDog", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
        Text("Network security assessment — desktop", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(20.dp))

        NetworkCard(network, onRefresh = { network = netCtx.current() })
        Spacer(Modifier.height(16.dp))

        // Depth selector
        Text("Port depth", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ScanDepth.entries.forEach { d ->
                FilterChip(selected = depth == d, onClick = { depth = d }, label = { Text(d.label) })
            }
        }
        Spacer(Modifier.height(16.dp))

        // Actions
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(
                onClick = { selected.clear(); controller.startDiscovery(config) },
                enabled = network?.cidr != null && !state.running,
            ) { Text("Discover hosts") }

            Button(
                onClick = { controller.scanHosts(selected.toList(), config) },
                enabled = selected.isNotEmpty() && !state.running,
            ) { Text("Scan selected (${selected.size})") }

            if (state.running) {
                OutlinedButton(onClick = { controller.cancel() }) { Text("Cancel") }
                Spacer(Modifier.width(4.dp))
                CircularProgressIndicator(modifier = Modifier.height(22.dp).width(22.dp))
                Text("  ${state.phase}  ${state.hostsDone}/${state.hostsTotal}", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            OutlinedButton(onClick = { selected.clear(); controller.reset(); network = netCtx.current() }) { Text("Reset") }
        }

        state.failureMessage?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }

        Spacer(Modifier.height(16.dp))

        // Discovered hosts (pickable)
        if (state.discoveredHosts.isNotEmpty()) {
            SectionTitle("Discovered hosts (${state.discoveredHosts.size})")
            val sortedHosts = state.discoveredHosts.sortedBy { runCatching { Cidr.ipToLong(it.ip) }.getOrDefault(Long.MAX_VALUE) }
            Column {
                Row {
                    OutlinedButton(onClick = { selected.clear(); selected.addAll(sortedHosts.map { it.ip }) }) { Text("Select all") }
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = { selected.clear() }) { Text("Clear") }
                }
                Spacer(Modifier.height(8.dp))
                sortedHosts.forEach { h ->
                    HostRow(
                        ip = h.ip,
                        subtitle = listOfNotNull(h.hostname, h.source).joinToString(" · "),
                        checked = selected.contains(h.ip),
                        onToggle = { if (selected.contains(h.ip)) selected.remove(h.ip) else selected.add(h.ip) },
                    )
                }
            }
            Spacer(Modifier.height(16.dp))
        }

        // Services / results
        if (state.services.isNotEmpty()) {
            SectionTitle("Services (${state.services.size})")
            state.services.groupBy { it.host }.toSortedMap(compareBy { runCatching { Cidr.ipToLong(it) }.getOrDefault(Long.MAX_VALUE) })
                .forEach { (host, svcs) ->
                    Text(host, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
                    svcs.sortedBy { it.port }.forEach { s ->
                        val prod = s.product
                        val desc = buildString {
                            append(s.port); append("/"); append(s.proto)
                            s.serviceName?.let { append("  "); append(it) }
                            prod?.product?.let { append("  "); append(it) }
                            prod?.version?.let { append(" "); append(it) }
                        }
                        Text("    $desc", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                    Spacer(Modifier.height(6.dp))
                }

            Spacer(Modifier.height(12.dp))
            Button(onClick = { controller.correlate() }, enabled = busy == null) {
                Text("Check vulnerabilities (OSV)")
            }
            busy?.let { Text("  $it", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            Spacer(Modifier.height(12.dp))
        }

        // Findings
        vuln?.let { v ->
            SectionTitle("Findings (${v.findings.size}${if (v.suppressed.isNotEmpty()) ", ${v.suppressed.size} suppressed" else ""})")
            if (v.findings.isEmpty()) {
                Text("No vulnerabilities correlated for the enumerated services.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            v.findings.sortedByDescending { it.priority }.forEach { f ->
                Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Text(
                        "[${f.severity}] ${f.cveId}  ${f.product.product}  ${f.host}:${f.port}",
                        fontWeight = FontWeight.Medium,
                    )
                    Text(
                        "priority ${f.priority} · ${f.state}" +
                            (f.cvssScore?.let { " · CVSS $it" } ?: "") +
                            (if (f.knownExploited) " · KEV" else ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    f.why.firstOrNull()?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    HorizontalDivider(Modifier.padding(top = 4.dp))
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun NetworkCard(network: NetworkInfo?, onRefresh: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant).padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Target network", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = onRefresh) { Text("Refresh") }
        }
        Spacer(Modifier.height(8.dp))
        if (network?.cidr == null) {
            Text("No active IPv4 LAN detected. Connect to a network and refresh.", color = MaterialTheme.colorScheme.error)
        } else {
            val c = network.cidr!!
            Text("Subnet: ${Cidr.longToIp(c.networkAddr)}/${c.prefixLength}  (${c.hostCount} hosts)", fontFamily = FontFamily.Monospace)
            Text("Local IP: ${network.localIp ?: "?"}   Gateway: ${network.gatewayIp ?: "?"}", fontFamily = FontFamily.Monospace)
            Text("Link: ${if (network.isWifi) "Wi-Fi" else "wired"}", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun HostRow(ip: String, subtitle: String, checked: Boolean, onToggle: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onToggle).padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = { onToggle() })
        Spacer(Modifier.width(8.dp))
        Column {
            Text(ip, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
            if (subtitle.isNotBlank()) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
    Box(Modifier.fillMaxWidth().height(1.dp).background(MaterialTheme.colorScheme.surfaceVariant))
}
