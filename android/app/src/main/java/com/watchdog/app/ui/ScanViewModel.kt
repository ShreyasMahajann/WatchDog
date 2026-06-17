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
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** The guided-flow stages, driven by user actions + live scan state. */
enum class Stage { Networks, Scope, Discovering, PickHost, Scanning, Findings, Settings }

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val networkContext = AndroidNetworkContext(app)
    private val wifiScanner = WifiScanner(app)
    private val settingsRepo = SettingsRepository(app)

    val runState: StateFlow<ScanRunState> = ScanStateHolder.state

    private val _stage = MutableStateFlow(Stage.Networks)
    val stage: StateFlow<Stage> = _stage.asStateFlow()

    private var stageBeforeSettings: Stage = Stage.Networks

    private val _network = MutableStateFlow<NetworkInfo?>(null)
    val network: StateFlow<NetworkInfo?> = _network.asStateFlow()

    private val _nearby = MutableStateFlow<List<WifiScanner.NearbyAp>>(emptyList())
    val nearby: StateFlow<List<WifiScanner.NearbyAp>> = _nearby.asStateFlow()

    val settings: StateFlow<Settings> =
        settingsRepo.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())

    var selectedDepth: ScanDepth = ScanDepth.TOP_1000
        private set
    var allowLargeSubnet: Boolean = false
        private set

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
        viewModelScope.launch {
            settingsRepo.settings.collect { selectedDepth = it.defaultDepth }
        }
    }

    fun refreshNetwork() {
        viewModelScope.launch {
            _network.value = networkContext.current()
            _nearby.value = wifiScanner.scan()
        }
    }

    fun setDepth(depth: ScanDepth) { selectedDepth = depth }
    fun setAllowLargeSubnet(value: Boolean) { allowLargeSubnet = value }

    fun goToScope() { _stage.value = Stage.Scope }

    fun startWholeNetwork() {
        ScanForegroundService.startWholeNetwork(getApplication(), selectedDepth, allowLargeSubnet)
        _stage.value = Stage.Scanning
    }

    fun startSingleHost() {
        ScanForegroundService.startDiscovery(getApplication(), selectedDepth, allowLargeSubnet)
        _stage.value = Stage.Discovering
    }

    fun pickHost(ip: String) {
        ScanForegroundService.scanHost(getApplication(), ip, selectedDepth)
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
