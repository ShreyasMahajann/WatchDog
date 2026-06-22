package com.watchdog.app.ui.networks

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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

@Composable
fun NetworksScreen(
    network: NetworkInfo?,
    nearby: List<WifiScanner.NearbyAp>,
    wifiStatus: WifiScanner.Status,
    onContinue: () -> Unit,
    onRefresh: () -> Unit,
    onGrantPermission: () -> Unit,
    onOpenLocationSettings: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val cidr = network?.cidr
    val scannable = cidr != null
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
        Column(Modifier.verticalScroll(rememberScrollState())) {
            if (scannable) {
                LabeledCard(
                    label = "Connected — this network is scannable",
                    value = buildString {
                        append(network?.ssid ?: "Wi-Fi")
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
            InfoBanner("You can only scan the network you're joined to. Nearby networks are shown for context — connect to one in Android settings to scan it.")
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
                WifiScanner.Status.OK -> {
                    nearby.forEachIndexed { i, ap ->
                        Row(
                            modifier = Modifier.fillMaxWidth().height(48.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(ap.ssid, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.weight(1f))
                            Text(
                                if (ap.connected) "connected" else "join to scan",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.width(8.dp))
                            Text("${ap.signalLevel}/4", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (i < nearby.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = onRefresh) { Text("Rescan") }
                }
            }
        }
    }
}

@Composable
private fun ActionHint(text: String, action: String, onAction: () -> Unit) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(4.dp))
    TextButton(onClick = onAction) { Text(action) }
}
