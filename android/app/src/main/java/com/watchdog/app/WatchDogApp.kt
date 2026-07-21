package com.watchdog.app

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.watchdog.app.net.Cidr
import com.watchdog.app.share.ScanShare
import com.watchdog.app.ui.ScanViewModel
import com.watchdog.app.ui.Stage
import com.watchdog.app.ui.history.HistoryScreen
import com.watchdog.app.ui.hosts.HostsScreen
import com.watchdog.app.ui.networks.NetworksScreen
import com.watchdog.app.ui.results.DeviceDetailScreen
import com.watchdog.app.ui.results.ResultsScreen
import com.watchdog.app.ui.scan.ScanningScreen
import com.watchdog.app.ui.select.ChoosePortsScreen
import com.watchdog.app.ui.select.SelectDevicesScreen
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
    val updateStatus by vm.updateStatus.collectAsStateWithLifecycle()
    val isRefreshing by vm.isRefreshing.collectAsStateWithLifecycle()
    val selectedDevices by vm.selectedDevices.collectAsStateWithLifecycle()
    val resultHosts by vm.resultHosts.collectAsStateWithLifecycle()
    val resultObservations by vm.resultObservations.collectAsStateWithLifecycle()
    val resultFindings by vm.resultFindings.collectAsStateWithLifecycle()
    val selectedHost by vm.selectedHost.collectAsStateWithLifecycle()
    val vulnState by vm.vulnCheckState.collectAsStateWithLifecycle()
    val correlationTargets by vm.correlationTargets.collectAsStateWithLifecycle()
    val recentScans by vm.recentScans.collectAsStateWithLifecycle()

    val context = LocalContext.current
    val discoveredHosts = runState.discoveredHosts.sortedBy { runCatching { Cidr.ipToLong(it.ip) }.getOrDefault(Long.MAX_VALUE) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { vm.refreshNetwork() }

    LaunchedEffect(Unit) {
        permissionLauncher.launch(runtimePermissions())
    }

    // Returning from the Android Wi-Fi panel resumes the app — re-detect the
    // network so the target updates to whatever the user just joined.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && vm.stage.value == Stage.Networks) {
                vm.refreshNetwork()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    BackHandler(enabled = stage != Stage.Networks && stage != Stage.Scanning) {
        when (stage) {
            Stage.Discovering -> vm.startOver()
            Stage.SelectDevices -> vm.startOver()
            Stage.ChoosePorts -> vm.backToSelectDevices()
            Stage.Results -> vm.startOver()
            Stage.DeviceDetail -> vm.backToResults()
            Stage.History -> vm.startOver()
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
                updateStatus = updateStatus,
                isRefreshing = isRefreshing,
                onContinue = vm::startDiscovery,
                onRefresh = vm::refreshNetwork,
                onGrantPermission = { permissionLauncher.launch(runtimePermissions()) },
                onOpenLocationSettings = {
                    context.startActivity(
                        Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                },
                onSwitchNetwork = {
                    val action = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        Settings.Panel.ACTION_WIFI
                    } else {
                        Settings.ACTION_WIFI_SETTINGS
                    }
                    context.startActivity(
                        Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                },
                onGetUpdate = { url ->
                    context.startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse(url))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                },
                onOpenHistory = vm::openHistory,
                onOpenSettings = vm::openSettings,
            )
            Stage.Discovering -> HostsScreen(
                hosts = discoveredHosts,
                discovering = true,
                onSelect = null,
                onBack = vm::startOver,
                onCancel = vm::startOver,
                onStop = vm::stopDiscovery,
            )
            Stage.SelectDevices -> SelectDevicesScreen(
                hosts = discoveredHosts,
                selected = selectedDevices,
                onToggle = vm::toggleDevice,
                onSelectAll = vm::selectAll,
                onClear = vm::clearSelection,
                onRediscover = vm::rediscover,
                onContinue = vm::proceedToPorts,
                onBack = vm::startOver,
            )
            Stage.ChoosePorts -> ChoosePortsScreen(
                selectedDepth = selectedDepth,
                onDepthChange = vm::setDepth,
                deviceCount = selectedDevices.size,
                onStart = vm::startScanSelected,
                onBack = vm::backToSelectDevices,
            )
            Stage.Scanning -> ScanningScreen(state = runState, onCancel = vm::cancel)
            Stage.Results -> ResultsScreen(
                scanNetwork = network?.ssid,
                hosts = resultHosts,
                observations = resultObservations,
                onOpenDevice = vm::openDevice,
                onShare = { ScanShare.share(context, ScanShare.reportText(resultHosts, resultObservations, resultFindings)) },
                onDone = vm::startOver,
            )
            Stage.DeviceDetail -> {
                val host = selectedHost
                if (host != null) {
                    val deviceObs = resultObservations.filter { it.host == host }
                    val deviceFindings = resultFindings.filter { it.host == host }
                    val hostRow = resultHosts.find { it.ip == host }
                    DeviceDetailScreen(
                        host = host,
                        hostname = hostRow?.hostname,
                        discoverySource = hostRow?.discoverySources,
                        osGuess = hostRow?.osGuess,
                        observations = deviceObs,
                        findings = deviceFindings,
                        vulnState = vulnState,
                        targets = correlationTargets,
                        onCheck = vm::checkVulnerabilities,
                        onDeepRescan = vm::deepRescanDevice,
                        onShare = { ScanShare.share(context, ScanShare.deviceText(host, deviceObs, deviceFindings)) },
                        onBack = vm::backToResults,
                    )
                }
            }
            Stage.History -> HistoryScreen(
                scans = recentScans,
                onOpen = vm::openHistoryScan,
                onDelete = vm::deleteScan,
                onExport = { id -> vm.exportScan(id, context) },
                onBack = vm::startOver,
            )
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
