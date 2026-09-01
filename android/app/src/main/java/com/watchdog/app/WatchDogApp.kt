package com.watchdog.app

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.widget.Toast
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
import com.watchdog.app.ui.devicewatch.DeviceWatchDetailScreen
import com.watchdog.app.ui.devicewatch.DeviceWatchScreen
import com.watchdog.app.ui.devicewatch.DeviceWatchViewModel
import com.watchdog.app.ui.history.HistoryScreen
import com.watchdog.app.ui.home.HomeScreen
import com.watchdog.app.ui.hosts.HostsScreen
import com.watchdog.app.ui.networks.NetworksScreen
import com.watchdog.app.ui.results.DeviceDetailScreen
import com.watchdog.app.ui.results.ResultsScreen
import com.watchdog.app.ui.scan.ScanningScreen
import com.watchdog.app.ui.select.ChoosePortsScreen
import com.watchdog.app.ui.select.SelectDevicesScreen
import com.watchdog.app.ui.settings.SettingsScreen
import com.watchdog.app.ui.wpa.WpaCaptureDetailScreen
import com.watchdog.app.ui.wpa.WpaCaptureScreen
import com.watchdog.app.ui.wpa.WpaCapturesScreen
import com.watchdog.app.ui.wpa.WpaDiagnosticsScreen
import com.watchdog.app.ui.wpa.WpaHubScreen
import com.watchdog.app.ui.wpa.WpaKeyScreen
import com.watchdog.app.ui.wpa.WpaViewModel

@Composable
fun WatchDogApp(
    vm: ScanViewModel = viewModel(),
    wpaVm: WpaViewModel? = null,
    deviceWatchVm: DeviceWatchViewModel = viewModel(),
) {
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
    val resultScan by vm.resultScan.collectAsStateWithLifecycle()
    val dwNetwork by deviceWatchVm.network.collectAsStateWithLifecycle()
    val dwDevices by deviceWatchVm.devices.collectAsStateWithLifecycle()
    val dwScanning by deviceWatchVm.scanning.collectAsStateWithLifecycle()
    val dwMessage by deviceWatchVm.message.collectAsStateWithLifecycle()
    val dwSelectedId by deviceWatchVm.selectedId.collectAsStateWithLifecycle()

    val context = LocalContext.current
    val discoveredHosts = runState.discoveredHosts.sortedBy { runCatching { Cidr.ipToLong(it.ip) }.getOrDefault(Long.MAX_VALUE) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { vm.refreshNetwork() }

    LaunchedEffect(Unit) {
        permissionLauncher.launch(runtimePermissions())
    }

    // Surface Device Watch scan summaries as toasts.
    LaunchedEffect(dwMessage) {
        dwMessage?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            deviceWatchVm.consumeMessage()
        }
    }

    // Returning from the Android Wi-Fi panel resumes the app — re-detect the
    // network so the target updates to whatever the user just joined. Only fires
    // on the NetScan screen (guarded by vm.stage.value == Stage.Networks below).
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                when (vm.stage.value) {
                    Stage.Networks -> vm.refreshNetwork()
                    Stage.DeviceWatch -> deviceWatchVm.refreshNetwork()
                    else -> {}
                }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    BackHandler(enabled = stage != Stage.Home && stage != Stage.Scanning) {
        when (stage) {
            Stage.Networks -> vm.goHome()
            Stage.Discovering -> vm.startOver()
            Stage.SelectDevices -> vm.startOver()
            Stage.ChoosePorts -> vm.backToSelectDevices()
            Stage.Results -> vm.startOver()
            Stage.DeviceDetail -> vm.backToResults()
            Stage.History -> vm.startOver()
            Stage.Settings -> vm.closeSettings()
            Stage.WpaHub -> vm.goHome()
            Stage.WpaDiagnostics -> vm.backToWpaHub()
            Stage.WpaCaptures -> vm.backToWpaHub()
            Stage.WpaCaptureDetail -> vm.backToWpaCaptures()
            Stage.WpaKey -> vm.backToWpaHub()
            Stage.WpaCapture -> vm.backToWpaHub()
            Stage.DeviceWatch -> vm.goHome()
            Stage.DeviceWatchDetail -> vm.backToDeviceWatch()
            else -> {}
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        when (stage) {
            Stage.Home -> HomeScreen(
                appVersion = vm.appVersion,
                onOpenNetScan = vm::openNetScan,
                onOpenWpa = vm::openWpa,
                onOpenDeviceWatch = vm::openDeviceWatch,
                onOpenSettings = vm::openSettings,
            )
            Stage.Networks -> NetworksScreen(
                network = network,
                nearby = nearby,
                wifiStatus = wifiStatus,
                updateStatus = updateStatus,
                isRefreshing = isRefreshing,
                appVersion = vm.appVersion,
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
                scanName = resultScan?.name,
                hosts = resultHosts,
                observations = resultObservations,
                findings = resultFindings,
                vulnState = vulnState,
                targets = correlationTargets,
                onCheckAll = vm::checkAllVulnerabilities,
                onOpenDevice = vm::openDevice,
                onRename = { name -> vm.currentScanId.value?.let { vm.renameScan(it, name) } },
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
                onRename = vm::renameScan,
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
            Stage.WpaHub,
            Stage.WpaDiagnostics,
            Stage.WpaCaptures,
            Stage.WpaCaptureDetail,
            Stage.WpaKey,
            Stage.WpaCapture,
            -> WpaFlow(stage = stage, appVm = vm, injectedVm = wpaVm)
            Stage.DeviceWatch -> DeviceWatchScreen(
                appVersion = vm.appVersion,
                network = dwNetwork,
                devices = dwDevices,
                scanning = dwScanning,
                onScanNow = deviceWatchVm::scanNow,
                onOpenDevice = { id -> deviceWatchVm.selectDevice(id); vm.openDeviceWatchDetail() },
                onTrust = deviceWatchVm::trust,
                onBack = vm::goHome,
            )
            Stage.DeviceWatchDetail -> {
                val device = dwDevices.find { it.id == dwSelectedId }
                if (device == null) {
                    vm.backToDeviceWatch()
                } else {
                    DeviceWatchDetailScreen(
                        device = device,
                        onRename = { name -> deviceWatchVm.rename(device.id, name) },
                        onTrust = { deviceWatchVm.trust(device.id) },
                        onUntrust = { deviceWatchVm.untrust(device.id) },
                        onForget = { deviceWatchVm.forget(device.id); vm.backToDeviceWatch() },
                        onBack = vm::backToDeviceWatch,
                    )
                }
            }
        }
    }
}

/**
 * Keep the optional WPA subsystem out of the startup path. Its ViewModel opens
 * encrypted preferences and WPA-specific Room state, so it is created only
 * after the user enters a WPA screen.
 */
@Composable
private fun WpaFlow(
    stage: Stage,
    appVm: ScanViewModel,
    injectedVm: WpaViewModel?,
) {
    val wpaVm = injectedVm ?: viewModel()
    val report by wpaVm.report.collectAsStateWithLifecycle()
    val loading by wpaVm.loading.collectAsStateWithLifecycle()
    val captures by wpaVm.captures.collectAsStateWithLifecycle()
    val busy by wpaVm.busy.collectAsStateWithLifecycle()
    val keyConfigured by wpaVm.keyConfigured.collectAsStateWithLifecycle()
    val captureSupported by wpaVm.captureSupported.collectAsStateWithLifecycle()
    val message by wpaVm.message.collectAsStateWithLifecycle()
    val selectedCaptureId by wpaVm.selectedCaptureId.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let { wpaVm.importCapture(it) } }

    LaunchedEffect(message) {
        message?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            wpaVm.consumeMessage()
        }
    }

    when (stage) {
        Stage.WpaHub -> WpaHubScreen(
            appVersion = appVm.appVersion,
            captureCount = captures.size,
            keyConfigured = keyConfigured,
            captureSupported = captureSupported,
            onOpenDiagnostics = appVm::openWpaDiagnostics,
            onImport = { importLauncher.launch(arrayOf("*/*")) },
            onStartCapture = appVm::openWpaCapture,
            onOpenCaptures = appVm::openWpaCaptures,
            onOpenKey = appVm::openWpaKey,
            onBack = appVm::goHome,
        )
        Stage.WpaDiagnostics -> WpaDiagnosticsScreen(
            report = report,
            loading = loading,
            onRefresh = { wpaVm.refresh(activeRootCheck = false) },
            onTestRoot = wpaVm::testRootAccess,
            onBack = appVm::backToWpaHub,
        )
        Stage.WpaCaptures -> WpaCapturesScreen(
            captures = captures,
            busy = busy,
            onOpen = { id -> wpaVm.selectCapture(id); appVm.openWpaCaptureDetail() },
            onRefresh = wpaVm::refreshResults,
            onBack = appVm::backToWpaHub,
        )
        Stage.WpaCaptureDetail -> {
            val capture = captures.find { it.id == selectedCaptureId }
            if (capture == null) {
                LaunchedEffect(Unit) { appVm.backToWpaCaptures() }
            } else {
                WpaCaptureDetailScreen(
                    capture = capture,
                    busy = busy,
                    onSubmit = { wpaVm.submit(capture.id) },
                    onRefresh = wpaVm::refreshResults,
                    onDelete = { wpaVm.deleteCapture(capture); appVm.backToWpaCaptures() },
                    onBack = appVm::backToWpaCaptures,
                )
            }
        }
        Stage.WpaKey -> WpaKeyScreen(
            configured = keyConfigured,
            onSave = wpaVm::saveKey,
            onClear = wpaVm::clearKey,
            onBack = appVm::backToWpaHub,
        )
        Stage.WpaCapture -> WpaCaptureScreen(
            interfaces = wpaVm.captureInterfaces(),
            busy = busy,
            onStart = { iface, channel, duration -> wpaVm.startCapture(iface, channel, duration) },
            onBack = appVm::backToWpaHub,
        )
        else -> Unit
    }
}

private fun runtimePermissions(): Array<String> {
    val perms = mutableListOf<String>()
    // Scan results require location access even on API 33+ on many OEM builds,
    // so we always request COARSE + FINE together; Android 12+ ignores a request
    // for FINE alone. NEARBY_WIFI_DEVICES is additive on API 33+.
    perms += Manifest.permission.ACCESS_COARSE_LOCATION
    perms += Manifest.permission.ACCESS_FINE_LOCATION
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        perms += Manifest.permission.POST_NOTIFICATIONS
        perms += Manifest.permission.NEARBY_WIFI_DEVICES
    }
    return perms.toTypedArray()
}
