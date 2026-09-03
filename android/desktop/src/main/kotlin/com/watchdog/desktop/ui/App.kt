package com.watchdog.desktop.ui

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
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.settings.Settings
import com.watchdog.desktop.data.DesktopScanStore
import com.watchdog.desktop.data.DesktopSettingsStore
import com.watchdog.desktop.net.DesktopNetworkContext
import com.watchdog.desktop.scan.DesktopScanController

enum class DesktopScreen(val label: String) {
    NetScan("NetScan"),
    History("History"),
    DeviceWatch("Device Watch"),
    Wpa("WPA Handshake"),
    Settings("Settings"),
}

/**
 * Desktop app shell: a top nav bar plus the selected screen. All screens share
 * one [DesktopScanController], sqlite [DesktopScanStore], and [DesktopSettingsStore].
 */
@Composable
fun App() {
    val scope = rememberCoroutineScope()
    val netCtx = remember { DesktopNetworkContext() }
    val scanStore = remember { DesktopScanStore() }
    val settingsStore = remember { DesktopSettingsStore() }
    val controller = remember { DesktopScanController(scope, netCtx, scanStore, settingsStore) }
    val settings by settingsStore.settings.collectAsState(initial = settingsStore.current())

    var screen by remember { mutableStateOf(DesktopScreen.NetScan) }

    Column(Modifier.fillMaxSize()) {
        TopNav(screen, onSelect = { screen = it })
        HorizontalDivider()
        Box(Modifier.fillMaxSize()) {
            when (screen) {
                DesktopScreen.NetScan -> NetScanScreen(controller, netCtx, settings)
                DesktopScreen.History -> HistoryScreen(
                    controller = controller,
                    scanStore = scanStore,
                    onOpened = { screen = DesktopScreen.NetScan },
                )
                DesktopScreen.DeviceWatch -> DeviceWatchScreen(netCtx)
                DesktopScreen.Wpa -> WpaScreen()
                DesktopScreen.Settings -> SettingsScreen(settingsStore, settings)
            }
        }
    }
}

@Composable
private fun TopNav(current: DesktopScreen, onSelect: (DesktopScreen) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("watchDog", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.width(16.dp))
        DesktopScreen.entries.forEach { s ->
            if (s == current) {
                FilledTonalButton(onClick = { onSelect(s) }) { Text(s.label) }
            } else {
                TextButton(onClick = { onSelect(s) }) { Text(s.label) }
            }
        }
    }
}
