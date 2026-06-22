package com.watchdog.app.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.watchdog.app.net.AndroidNetworkContext
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.net.WifiScanner
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.service.ScanForegroundService
import com.watchdog.app.service.ScanRunState
import com.watchdog.app.service.ScanStateHolder
import com.watchdog.app.update.UpdateChecker
import com.watchdog.app.update.UpdateStatus
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** The guided-flow stages, driven by user actions + live scan state. */
enum class Stage { Networks, Scope, Discovering, PickHost, Scanning, Findings, Settings }

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val networkContext = AndroidNetworkContext(app)
    private val wifiScanner = WifiScanner(app)
    private val settingsRepo = SettingsRepository(app)

    val appVersion: String = readAppVersion(app)
    private val updateChecker = UpdateChecker(appVersion)

    private val _updateStatus = MutableStateFlow<UpdateStatus>(UpdateStatus.Unknown)
    val updateStatus: StateFlow<UpdateStatus> = _updateStatus.asStateFlow()

    val runState: StateFlow<ScanRunState> = ScanStateHolder.state

    private val _stage = MutableStateFlow(Stage.Networks)
    val stage: StateFlow<Stage> = _stage.asStateFlow()

    private var stageBeforeSettings: Stage = Stage.Networks

    private val _network = MutableStateFlow<NetworkInfo?>(null)
    val network: StateFlow<NetworkInfo?> = _network.asStateFlow()

    private val _nearby = MutableStateFlow<List<WifiScanner.NearbyAp>>(emptyList())
    val nearby: StateFlow<List<WifiScanner.NearbyAp>> = _nearby.asStateFlow()

    private val _wifiStatus = MutableStateFlow(WifiScanner.Status.EMPTY)
    val wifiStatus: StateFlow<WifiScanner.Status> = _wifiStatus.asStateFlow()

    val settings: StateFlow<Settings> =
        settingsRepo.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())

    private val _selectedDepth = MutableStateFlow(ScanDepth.TOP_1000)
    val selectedDepth: StateFlow<ScanDepth> = _selectedDepth.asStateFlow()

    private val _allowLargeSubnet = MutableStateFlow(false)
    val allowLargeSubnet: StateFlow<Boolean> = _allowLargeSubnet.asStateFlow()

    init {
        refreshNetwork()
        viewModelScope.launch {
            ScanStateHolder.state.collect { s ->
                when {
                    s.awaitingHostPick && _stage.value == Stage.Discovering -> _stage.value = Stage.PickHost
                    s.finished && _stage.value == Stage.Scanning -> _stage.value = Stage.Findings
                }
            }
        }
        // Seed the depth from settings once; user changes take over after that.
        viewModelScope.launch { _selectedDepth.value = settingsRepo.settings.first().defaultDepth }
        // Keep the target/others list live: re-detect whenever the phone's network
        // changes, but only while the user is on a network-facing stage so a running
        // scan isn't disturbed.
        viewModelScope.launch {
            networkContext.changes().collect {
                if (_stage.value == Stage.Networks || _stage.value == Stage.Scope) refreshNetwork()
            }
        }
        // One-shot update check against the latest GitHub release.
        viewModelScope.launch { _updateStatus.value = updateChecker.check() }
    }

    fun refreshNetwork() {
        viewModelScope.launch {
            _network.value = networkContext.current()
            val result = wifiScanner.scan()
            _nearby.value = result.aps
            _wifiStatus.value = result.status
        }
    }

    fun setDepth(depth: ScanDepth) { _selectedDepth.value = depth }
    fun setAllowLargeSubnet(value: Boolean) { _allowLargeSubnet.value = value }

    fun goToScope() { _stage.value = Stage.Scope }

    fun startWholeNetwork() {
        ScanForegroundService.startWholeNetwork(getApplication(), _selectedDepth.value, _allowLargeSubnet.value)
        _stage.value = Stage.Scanning
    }

    fun startSingleHost() {
        ScanForegroundService.startDiscovery(getApplication(), _selectedDepth.value, _allowLargeSubnet.value)
        _stage.value = Stage.Discovering
    }

    fun pickHost(ip: String) {
        ScanForegroundService.scanHost(getApplication(), ip, _selectedDepth.value)
        _stage.value = Stage.Scanning
    }

    fun cancel() {
        ScanForegroundService.cancel(getApplication())
    }

    fun startOver() {
        ScanStateHolder.update { ScanRunState() }
        _stage.value = Stage.Networks
        refreshNetwork()
    }

    fun openSettings() {
        stageBeforeSettings = _stage.value
        _stage.value = Stage.Settings
    }

    fun closeSettings() { _stage.value = stageBeforeSettings }

    fun saveMode(mode: CorrelatorMode) { viewModelScope.launch { settingsRepo.setMode(mode) } }
    fun saveServer(url: String, token: String) { viewModelScope.launch { settingsRepo.setServer(url, token) } }
    fun saveDefaultDepth(depth: ScanDepth) { viewModelScope.launch { settingsRepo.setDepth(depth) } }
}

private fun readAppVersion(app: Application): String =
    try {
        @Suppress("DEPRECATION")
        app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: "0.0.0"
    } catch (e: Exception) {
        "0.0.0"
    }
