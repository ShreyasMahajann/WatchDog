package com.watchdog.app.ui.results

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.correlate.CorrelationTarget
import com.watchdog.app.data.room.HostEntity
import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.ui.ScanViewModel
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.LabeledCard
import com.watchdog.app.ui.common.RenameScanDialog
import com.watchdog.app.ui.common.ScreenChrome

private enum class ResultsMode { Device, Service }

@Composable
fun ResultsScreen(
    scanNetwork: String?,
    scanName: String?,
    hosts: List<HostEntity>,
    observations: List<ServiceObservation>,
    findings: List<Finding>,
    vulnState: ScanViewModel.VulnCheckState,
    targets: List<CorrelationTarget>,
    onCheckAll: (CorrelationTarget) -> Unit,
    onOpenDevice: (String) -> Unit,
    onRename: (String) -> Unit,
    onShare: () -> Unit,
    onDone: () -> Unit,
) {
    val byHost = remember(observations) { observations.groupBy { it.host } }
    val findingsByHost = remember(findings) { findings.filter { !it.suppressed }.groupBy { it.host } }
    val activeFindings = remember(findings) { findings.count { !it.suppressed } }
    val sortedHosts = remember(hosts) {
        hosts.sortedBy { runCatching { Cidr.ipToLong(it.ip) }.getOrDefault(Long.MAX_VALUE) }
    }
    val serviceGroups = remember(observations) { ResultsFilter.groupByService(observations) }

    var showRename by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf(ResultsMode.Device) }

    if (showRename) {
        RenameScanDialog(
            initial = scanName,
            onConfirm = { onRename(it); showRename = false },
            onDismiss = { showRename = false },
        )
    }
    ScreenChrome(
        title = scanName ?: "Results",
        subtitle = scanNetwork,
        onBack = null,
        primaryLabel = "Done",
        onPrimary = onDone,
        secondaryLabel = "Share report",
        onSecondary = onShare,
    ) {
        Column(Modifier.fillMaxSize()) {
            TextButton(onClick = { showRename = true }) {
                Text(if (scanName == null) "Name this scan" else "Rename scan")
            }
            Spacer(Modifier.height(4.dp))
            LabeledCard(
                label = "Summary",
                value = "${hosts.size} devices · ${observations.size} services · $activeFindings findings",
            )
            Spacer(Modifier.height(12.dp))
            VulnSection(vulnState, targets, hasFindings = activeFindings > 0, onCheckAll)
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search ip, port, service, product") },
                singleLine = true,
                trailingIcon = {
                    if (query.isNotEmpty()) TextButton(onClick = { query = "" }) { Text("Clear") }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = mode == ResultsMode.Device,
                    onClick = { mode = ResultsMode.Device },
                    label = { Text("By device") },
                )
                FilterChip(
                    selected = mode == ResultsMode.Service,
                    onClick = { mode = ResultsMode.Service },
                    label = { Text("By service") },
                )
            }
            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            val listModifier = Modifier.weight(1f).fillMaxWidth()
            when (mode) {
                ResultsMode.Device -> DeviceList(listModifier, sortedHosts, byHost, findingsByHost, query, onOpenDevice)
                ResultsMode.Service -> ServiceList(listModifier, serviceGroups, query, onOpenDevice)
            }
        }
    }
}

@Composable
private fun VulnSection(
    vulnState: ScanViewModel.VulnCheckState,
    targets: List<CorrelationTarget>,
    hasFindings: Boolean,
    onCheckAll: (CorrelationTarget) -> Unit,
) {
    val running = vulnState is ScanViewModel.VulnCheckState.Running
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        targets.forEach { t ->
            val base = if (t == CorrelationTarget.OSV) "OSV" else "my server"
            Button(onClick = { onCheckAll(t) }, enabled = !running) {
                Text(if (hasFindings) "Re-check all · $base" else "Check all devices · $base")
            }
        }
    }
    when (vulnState) {
        is ScanViewModel.VulnCheckState.Running -> {
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        is ScanViewModel.VulnCheckState.Error -> {
            Spacer(Modifier.height(8.dp))
            InfoBanner(vulnState.message)
        }
        else -> {}
    }
}

@Composable
private fun DeviceList(
    modifier: Modifier,
    sortedHosts: List<HostEntity>,
    byHost: Map<String, List<ServiceObservation>>,
    findingsByHost: Map<String, List<Finding>>,
    query: String,
    onOpenDevice: (String) -> Unit,
) {
    // A device shows when it matches by ip/hostname (then all its services show)
    // or when at least one of its services matches (then only those show).
    val rows = sortedHosts.mapNotNull { h ->
        val services = byHost[h.ip].orEmpty()
        val hostHit = ResultsFilter.hostMatches(h.ip, h.hostname, query)
        val shownServices =
            if (query.isBlank() || hostHit) services
            else services.filter { ResultsFilter.serviceMatches(it, query) }
        if (query.isBlank() || hostHit || shownServices.isNotEmpty()) h to shownServices else null
    }

    if (rows.isEmpty()) {
        EmptyResult("No devices match \"${query.trim()}\".")
        return
    }
    LazyColumn(modifier) {
        items(rows, key = { it.first.id }) { (h, services) ->
            Column(
                Modifier.fillMaxWidth()
                    .clickable { onOpenDevice(h.ip) }
                    .padding(vertical = 10.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(h.ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            h.hostname ?: "${services.size} service${if (services.size == 1) "" else "s"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    val fCount = findingsByHost[h.ip]?.size ?: 0
                    if (fCount > 0) {
                        Text(
                            "⚠ $fCount",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(end = 8.dp),
                        )
                    }
                    Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                services.forEach { o ->
                    Text(
                        serviceLine(o),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 8.dp, top = 2.dp),
                    )
                }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
private fun ServiceList(
    modifier: Modifier,
    groups: List<ServiceGroup>,
    query: String,
    onOpenDevice: (String) -> Unit,
) {
    val visible = groups.filter { ResultsFilter.serviceGroupMatches(it, query) }
    var expanded by remember { mutableStateOf(setOf<String>()) }

    if (visible.isEmpty()) {
        EmptyResult("No services match \"${query.trim()}\".")
        return
    }
    LazyColumn(modifier) {
        visible.forEach { g ->
            val isOpen = query.isNotBlank() || g.label in expanded
            item(key = "hdr-${g.label}") {
                Row(
                    Modifier.fillMaxWidth()
                        .clickable {
                            expanded = if (g.label in expanded) expanded - g.label else expanded + g.label
                        }
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(if (isOpen) "▾" else "▸", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        g.label,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        "${g.hosts.size} host${if (g.hosts.size == 1) "" else "s"}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            if (isOpen) {
                items(g.hosts, key = { "${g.label}-$it" }) { ip ->
                    Row(
                        Modifier.fillMaxWidth()
                            .clickable { onOpenDevice(ip) }
                            .padding(vertical = 8.dp, horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        Text("›", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}

@Composable
private fun EmptyResult(message: String) {
    Spacer(Modifier.height(24.dp))
    Text(
        message,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.fillMaxWidth(),
    )
}

private fun serviceLine(o: ServiceObservation): String {
    val product = o.product?.let { "${it.product}${it.version?.let { v -> " $v" } ?: ""}" } ?: ""
    return "${o.port}/${o.proto}  ${o.serviceName ?: ""}  $product".trim().replace(Regex("\\s+"), " ")
}
