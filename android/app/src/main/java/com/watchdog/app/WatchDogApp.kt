package com.watchdog.app

import android.Manifest
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.watchdog.app.ui.ScanViewModel
import com.watchdog.app.ui.Stage
import com.watchdog.app.ui.findings.FindingsScreen
import com.watchdog.app.ui.hosts.HostsScreen
import com.watchdog.app.ui.networks.NetworksScreen
import com.watchdog.app.ui.scan.ScanningScreen
import com.watchdog.app.ui.scope.ScopeScreen
import com.watchdog.app.ui.settings.SettingsScreen

@Composable
fun WatchDogApp(vm: ScanViewModel = viewModel()) {
    val stage by vm.stage.collectAsStateWithLifecycle()
    val runState by vm.runState.collectAsStateWithLifecycle()
    val network by vm.network.collectAsStateWithLifecycle()
    val nearby by vm.nearby.collectAsStateWithLifecycle()
    val wifiStatus by vm.wifiStatus.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val selectedDepth by vm.selectedDepth.collectAsStateWithLifecycle()
    val allowLarge by vm.allowLargeSubnet.collectAsStateWithLifecycle()

    val context = LocalContext.current

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { vm.refreshNetwork() }

    LaunchedEffect(Unit) {
        permissionLauncher.launch(runtimePermissions())
    }

    BackHandler(enabled = stage != Stage.Networks && stage != Stage.Scanning) {
        when (stage) {
            Stage.Scope -> vm.startOver()
            Stage.Discovering, Stage.PickHost -> vm.goToScope()
            Stage.Findings -> vm.startOver()
            Stage.Settings -> vm.closeSettings()
            else -> {}
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        when (stage) {
            Stage.Networks -> NetworksScreen(
                network = network,
                nearby = nearby,
                wifiStatus = wifiStatus,
                onContinue = vm::goToScope,
                onRefresh = vm::refreshNetwork,
                onGrantPermission = { permissionLauncher.launch(runtimePermissions()) },
                onOpenLocationSettings = {
                    context.startActivity(
                        Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                },
                onOpenSettings = vm::openSettings,
            )
            Stage.Scope -> ScopeScreen(
                network = network,
                selectedDepth = selectedDepth,
                onDepthChange = vm::setDepth,
                allowLarge = allowLarge,
                onAllowLargeChange = vm::setAllowLargeSubnet,
                onWholeNetwork = vm::startWholeNetwork,
                onSingleHost = vm::startSingleHost,
                onBack = vm::startOver,
            )
            Stage.Discovering -> HostsScreen(
                hosts = runState.discoveredHosts,
                discovering = true,
                onSelect = null,
                onBack = vm::goToScope,
            )
            Stage.PickHost -> HostsScreen(
                hosts = runState.discoveredHosts,
                discovering = false,
                onSelect = vm::pickHost,
                onBack = vm::goToScope,
            )
            Stage.Scanning -> ScanningScreen(state = runState, onCancel = vm::cancel)
            Stage.Findings -> FindingsScreen(state = runState, onRestart = vm::startOver)
            Stage.Settings -> SettingsScreen(
                settings = settings,
                onSetMode = vm::saveMode,
                onSaveServer = vm::saveServer,
                onSetDepth = vm::saveDefaultDepth,
                onBack = vm::closeSettings,
            )
        }
    }
}

private fun runtimePermissions(): Array<String> {
    val perms = mutableListOf<String>()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        perms += Manifest.permission.POST_NOTIFICATIONS
        perms += Manifest.permission.NEARBY_WIFI_DEVICES
    } else {
        perms += Manifest.permission.ACCESS_FINE_LOCATION
    }
    return perms.toTypedArray()
}
