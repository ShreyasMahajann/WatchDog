package com.watchdog.app.ui.networks

import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.net.WifiScanner
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.LabeledCard
import com.watchdog.app.ui.common.ScreenChrome
import com.watchdog.app.update.UpdateStatus

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetworksScreen(
    network: NetworkInfo?,
    nearby: List<WifiScanner.NearbyAp>,
    wifiStatus: WifiScanner.Status,
    updateStatus: UpdateStatus,
    isRefreshing: Boolean,
    onContinue: () -> Unit,
    onRefresh: () -> Unit,
    onGrantPermission: () -> Unit,
    onOpenLocationSettings: () -> Unit,
    onSwitchNetwork: () -> Unit,
    onGetUpdate: (String) -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val cidr = network?.cidr
    val scannable = cidr != null
    val connectedSsid = network?.ssid
    ScreenChrome(
        title = "watchDog",
        subtitle = "Portable network security assessment",
        onBack = null,
        primaryLabel = if (scannable) "Continue" else "Refresh",
        primaryEnabled = true,
        onPrimary = if (scannable) onContinue else onRefresh,
        secondaryLabel = "Settings",
        onSecondary = onOpenSettings,
    ) {
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onOpenHistory) { Text("History") }
            }
            if (updateStatus is UpdateStatus.Available) {
                UpdateBanner(
                    version = updateStatus.latestVersion,
                    onGet = { onGetUpdate(updateStatus.releaseUrl) },
                )
                Spacer(Modifier.height(16.dp))
            }
            if (scannable) {
                LabeledCard(
                    label = "Target — currently connected",
                    value = buildString {
                        append(connectedSsid ?: "Wi-Fi")
                        append(" · ")
                        append("${Cidr.longToIp(cidr!!.networkAddr)}/${cidr.prefixLength}")
                    },
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "${cidr.hostCount} host addresses · your IP ${network?.localIp ?: "?"}" +
                        (network?.gatewayIp?.let { " · gateway $it" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else if (connectedSsid != null) {
                LabeledCard(
                    label = "Connected — not scannable yet",
                    value = connectedSsid,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Connected, but no IPv4 subnet was found — this network can't be scanned. Switch networks or Refresh.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                LabeledCard(
                    label = "No scannable network",
                    value = "Join a Wi-Fi network with an IPv4 subnet, then Refresh.",
                )
            }

            Spacer(Modifier.height(20.dp))
            Text(
                "Other networks in range",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(4.dp))
            InfoBanner("You can only scan the network you're joined to. Tap another network to switch to it — the target above updates once you've joined.")
            Spacer(Modifier.height(8.dp))

            when (wifiStatus) {
                WifiScanner.Status.NO_PERMISSION -> ActionHint(
                    text = "Grant the nearby-Wi-Fi permission to list networks in range.",
                    action = "Grant permission",
                    onAction = onGrantPermission,
                )
                WifiScanner.Status.LOCATION_OFF -> ActionHint(
                    text = "Android requires Location services to be ON to list Wi-Fi networks — even with permission granted.",
                    action = "Turn on Location",
                    onAction = onOpenLocationSettings,
                )
                WifiScanner.Status.EMPTY -> ActionHint(
                    text = "No networks cached yet (Wi-Fi scans are throttled by the OS).",
                    action = "Rescan",
                    onAction = onRefresh,
                )
                WifiScanner.Status.UNAVAILABLE -> ActionHint(
                    text = "Wi-Fi scanning isn't available right now.",
                    action = "Rescan",
                    onAction = onRefresh,
                )
                WifiScanner.Status.OK -> {
                    val others = nearby.filter { !it.connected }
                    if (others.isEmpty()) {
                        Text(
                            "No other networks in range.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    others.forEachIndexed { i, ap ->
                        Row(
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                                .clickable(onClick = onSwitchNetwork),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(ap.ssid, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.weight(1f))
                            Text("${ap.signalLevel}/4", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.width(8.dp))
                            Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (i < others.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = onRefresh) { Text("Rescan") }
                }
            }
        }
        }
    }
}

@Composable
private fun UpdateBanner(version: String, onGet: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Update available — $version", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(
                "You're not on the latest release. Open the repo to download it.",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(12.dp))
            Button(onClick = onGet) { Text("Get the latest release") }
        }
    }
}

@Composable
private fun ActionHint(text: String, action: String, onAction: () -> Unit) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(4.dp))
    TextButton(onClick = onAction) { Text(action) }
}
