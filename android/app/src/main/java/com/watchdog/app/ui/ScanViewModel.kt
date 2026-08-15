package com.watchdog.app.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.watchdog.app.correlate.CorrelationTarget
import com.watchdog.app.correlate.CorrelatorFactory
import com.watchdog.app.data.room.HostEntity
import com.watchdog.app.data.room.ScanEntity
import com.watchdog.app.data.room.ScanRepository
import com.watchdog.app.data.room.WatchDogDatabase
import com.watchdog.app.net.AndroidNetworkContext
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.net.WifiScanner
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.service.ScanForegroundService
import com.watchdog.app.service.ScanRunState
import com.watchdog.app.service.ScanStateHolder
import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsRepository
import com.watchdog.app.update.UpdateChecker
import com.watchdog.app.update.UpdateStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * The iterative guided flow: discover devices → select some → choose ports → scan →
 * device-centric results → on-demand vuln check. Correlation is no longer part of the
 * scan; it runs per device on request and its findings are additive.
 */
enum class Stage {
    Home, Networks, Discovering, SelectDevices, ChoosePorts, Scanning, Results, DeviceDetail, History, Settings,
    WpaHub, WpaDiagnostics, WpaCaptures, WpaCaptureDetail, WpaKey, WpaCapture,
    DeviceWatch, DeviceWatchDetail,
}

/** Stages a live port-scan can terminate from (finish/cancel/fail) → Results. */
private val FINISHABLE_STAGES = setOf(Stage.Scanning)

/** Minimum time the pull-to-refresh spinner stays up so its animation can settle. */
private const val MIN_REFRESH_SPINNER_MS = 600L

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val networkContext = AndroidNetworkContext(app)
    private val wifiScanner = WifiScanner(app)
    private val settingsRepo = SettingsRepository(app)
    private val repo = ScanRepository(WatchDogDatabase.get(app).dao())
    private val correlatorFactory = CorrelatorFactory(app)

    val appVersion: String = readAppVersion(app)
    private val updateChecker = UpdateChecker(appVersion)

    private val _updateStatus = MutableStateFlow<UpdateStatus>(UpdateStatus.Unknown)
    val updateStatus: StateFlow<UpdateStatus> = _updateStatus.asStateFlow()

    val runState: StateFlow<ScanRunState> = ScanStateHolder.state

    private val _stage = MutableStateFlow(Stage.Home)
    val stage: StateFlow<Stage> = _stage.asStateFlow()

    private var stageBeforeSettings: Stage = Stage.Home

    private val _network = MutableStateFlow<NetworkInfo?>(null)
    val network: StateFlow<NetworkInfo?> = _network.asStateFlow()

    private val _nearby = MutableStateFlow<List<WifiScanner.NearbyAp>>(emptyList())
    val nearby: StateFlow<List<WifiScanner.NearbyAp>> = _nearby.asStateFlow()

    private val _wifiStatus = MutableStateFlow(WifiScanner.Status.EMPTY)
    val wifiStatus: StateFlow<WifiScanner.Status> = _wifiStatus.asStateFlow()

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    val settings: StateFlow<Settings> =
        settingsRepo.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())

    private val _selectedDepth = MutableStateFlow(ScanDepth.TOP_1000)
    val selectedDepth: StateFlow<ScanDepth> = _selectedDepth.asStateFlow()

    // --- iterative-flow state --------------------------------------------------

    private val _selectedDevices = MutableStateFlow<Set<String>>(emptySet())
    val selectedDevices: StateFlow<Set<String>> = _selectedDevices.asStateFlow()

    private val _currentScanId = MutableStateFlow<Long?>(null)
    val currentScanId: StateFlow<Long?> = _currentScanId.asStateFlow()

    private val _selectedHost = MutableStateFlow<String?>(null)
    val selectedHost: StateFlow<String?> = _selectedHost.asStateFlow()

    sealed interface VulnCheckState {
        data object Idle : VulnCheckState
        data object Running : VulnCheckState
        data class Error(val message: String) : VulnCheckState
    }

    private val _vulnCheckState = MutableStateFlow<VulnCheckState>(VulnCheckState.Idle)
    val vulnCheckState: StateFlow<VulnCheckState> = _vulnCheckState.asStateFlow()

    private val _correlationTargets = MutableStateFlow(listOf(CorrelationTarget.OSV))
    val correlationTargets: StateFlow<List<CorrelationTarget>> = _correlationTargets.asStateFlow()

    @OptIn(ExperimentalCoroutinesApi::class)
    val resultHosts: StateFlow<List<HostEntity>> = _currentScanId
        .flatMapLatest { id -> if (id == null) flowOf(emptyList()) else repo.observeHosts(id) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    @OptIn(ExperimentalCoroutinesApi::class)
    val resultObservations: StateFlow<List<ServiceObservation>> = _currentScanId
        .flatMapLatest { id -> if (id == null) flowOf(emptyList()) else repo.observeObservations(id) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    @OptIn(ExperimentalCoroutinesApi::class)
    val resultFindings: StateFlow<List<Finding>> = _currentScanId
        .flatMapLatest { id -> if (id == null) flowOf(emptyList()) else repo.observeFindings(id) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    @OptIn(ExperimentalCoroutinesApi::class)
    val resultScan: StateFlow<ScanEntity?> = _currentScanId
        .flatMapLatest { id -> if (id == null) flowOf(null) else repo.observeScan(id) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val recentScans: StateFlow<List<ScanEntity>> =
        repo.observeRecentScans().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        refreshNetwork()
        viewModelScope.launch {
            ScanStateHolder.state.collect { s ->
                when {
                    s.awaitingHostPick && _stage.value == Stage.Discovering -> _stage.value = Stage.SelectDevices
                    s.finished && _stage.value in FINISHABLE_STAGES -> {
                        _currentScanId.value = s.scanId
                        _stage.value = Stage.Results
                    }
                }
            }
        }
        // Seed the depth from settings once; user changes take over after that.
        viewModelScope.launch { _selectedDepth.value = settingsRepo.settings.first().defaultDepth }
        // Live network + nearby list on the home screen.
        viewModelScope.launch {
            networkContext.changes().collect {
                if (_stage.value == Stage.Networks) refreshNetwork()
            }
        }
        viewModelScope.launch {
            wifiScanner.observe().collect { result ->
                _nearby.value = result.aps
                _wifiStatus.value = result.status
            }
        }
        // Which correlation targets are available (OSV always; own-server if configured).
        viewModelScope.launch { _correlationTargets.value = correlatorFactory.availableTargets() }
        // Update check against the latest GitHub release (also re-run on refresh).
        checkForUpdate()
    }

    /** Re-check the latest GitHub release; result surfaces via [updateStatus]. */
    private fun checkForUpdate() {
        viewModelScope.launch { _updateStatus.value = updateChecker.check() }
    }

    fun refreshNetwork() {
        checkForUpdate()
        viewModelScope.launch {
            _isRefreshing.value = true
            val startedAt = System.currentTimeMillis()
            try {
                _network.value = networkContext.current()
                wifiScanner.rescan()
                val result = wifiScanner.scan()
                _nearby.value = result.aps
                _wifiStatus.value = result.status
            } finally {
                // These reads hit cache and return within a frame; without a floor
                // the spinner flips off instantly and PullToRefreshBox strands its
                // indicator mid-pull instead of animating and settling.
                val elapsed = System.currentTimeMillis() - startedAt
                if (elapsed < MIN_REFRESH_SPINNER_MS) delay(MIN_REFRESH_SPINNER_MS - elapsed)
                _isRefreshing.value = false
            }
        }
    }

    fun setDepth(depth: ScanDepth) { _selectedDepth.value = depth }

    // --- top-level navigation --------------------------------------------------

    fun openNetScan() { _stage.value = Stage.Networks; refreshNetwork() }
    fun goHome() { _stage.value = Stage.Home }

    // --- WPA handshake tool ----------------------------------------------------

    fun openWpa() { _stage.value = Stage.WpaHub }
    fun openWpaDiagnostics() { _stage.value = Stage.WpaDiagnostics }
    fun openWpaCaptures() { _stage.value = Stage.WpaCaptures }
    fun openWpaCaptureDetail() { _stage.value = Stage.WpaCaptureDetail }
    fun openWpaKey() { _stage.value = Stage.WpaKey }
    fun openWpaCapture() { _stage.value = Stage.WpaCapture }
    fun backToWpaHub() { _stage.value = Stage.WpaHub }
    fun backToWpaCaptures() { _stage.value = Stage.WpaCaptures }

    // --- Device Watch tool -----------------------------------------------------

    fun openDeviceWatch() { _stage.value = Stage.DeviceWatch }
    fun openDeviceWatchDetail() { _stage.value = Stage.DeviceWatchDetail }
    fun backToDeviceWatch() { _stage.value = Stage.DeviceWatch }

    // --- discovery + selection -------------------------------------------------

    fun startDiscovery() {
        _selectedDevices.value = emptySet()
        ScanForegroundService.startDiscovery(getApplication(), _selectedDepth.value)
        _stage.value = Stage.Discovering
    }

    fun rediscover() = startDiscovery()

    /** Stop discovery early and go select from whatever's been found (controller flips to awaitingHostPick). */
    fun stopDiscovery() { ScanForegroundService.stopDiscovery(getApplication()) }

    fun toggleDevice(ip: String) {
        _selectedDevices.value = _selectedDevices.value.toMutableSet().apply { if (!add(ip)) remove(ip) }
    }

    fun selectAll() { _selectedDevices.value = runState.value.discoveredHosts.map { it.ip }.toSet() }
    fun clearSelection() { _selectedDevices.value = emptySet() }

    fun proceedToPorts() { if (_selectedDevices.value.isNotEmpty()) _stage.value = Stage.ChoosePorts }
    fun backToSelectDevices() { _stage.value = Stage.SelectDevices }

    fun startScanSelected() {
        ScanForegroundService.scanHosts(getApplication(), _selectedDevices.value.toList(), _selectedDepth.value)
        _currentScanId.value = ScanStateHolder.current().scanId
        _stage.value = Stage.Scanning
    }

    // --- results + on-demand vuln check ---------------------------------------

    fun openDevice(host: String) {
        _selectedHost.value = host
        _vulnCheckState.value = VulnCheckState.Idle
        _stage.value = Stage.DeviceDetail
    }

    fun backToResults() { _selectedHost.value = null; _stage.value = Stage.Results }

    fun checkVulnerabilities(target: CorrelationTarget) {
        val scanId = _currentScanId.value ?: return
        val host = _selectedHost.value ?: return
        viewModelScope.launch {
            _vulnCheckState.value = VulnCheckState.Running
            try {
                val obs = repo.observeObservations(scanId, host).first()
                val response = correlatorFactory.create(target).correlate(obs)
                repo.saveFindings(scanId, response.findings + response.suppressed)
                _vulnCheckState.value = VulnCheckState.Idle
            } catch (e: Exception) {
                _vulnCheckState.value = VulnCheckState.Error(e.message ?: "Check failed")
            }
        }
    }

    /**
     * Correlate every observed service in the current scan at once and persist the
     * findings. Clears prior findings first so a re-run is a clean recompute rather
     * than an append. This is what turns the scan-wide "0 findings" into real output.
     */
    fun checkAllVulnerabilities(target: CorrelationTarget) {
        val scanId = _currentScanId.value ?: return
        viewModelScope.launch {
            _vulnCheckState.value = VulnCheckState.Running
            try {
                val obs = repo.observeObservations(scanId).first()
                val response = correlatorFactory.create(target).correlate(obs)
                repo.clearFindings(scanId)
                repo.saveFindings(scanId, response.findings + response.suppressed)
                _vulnCheckState.value = VulnCheckState.Idle
            } catch (e: Exception) {
                _vulnCheckState.value = VulnCheckState.Error(e.message ?: "Check failed")
            }
        }
    }

    fun deepRescanDevice() {
        val host = _selectedHost.value ?: return
        val scanId = _currentScanId.value ?: return
        // Point the live scan state at this scan with cleared terminal flags, so the
        // re-scan actually runs (works for a just-finished scan and a reopened history one).
        ScanStateHolder.update {
            (if (it.scanId == scanId) it else ScanRunState(scanId = scanId)).copy(
                running = true, finished = false, cancelled = false, awaitingHostPick = false,
                hostsTotal = 1, hostsDone = 0, currentHost = null,
            )
        }
        ScanForegroundService.scanHosts(getApplication(), listOf(host), ScanDepth.TOP_1000)
        _stage.value = Stage.Scanning
    }

    // --- history ---------------------------------------------------------------

    fun openHistory() { _stage.value = Stage.History }
    fun openHistoryScan(scanId: Long) { _currentScanId.value = scanId; _stage.value = Stage.Results }
    fun deleteScan(scanId: Long) { viewModelScope.launch { repo.deleteScan(scanId) } }
    fun renameScan(scanId: Long, name: String) {
        viewModelScope.launch { repo.renameScan(scanId, name.trim().ifBlank { null }) }
    }

    fun exportScan(scanId: Long, context: android.content.Context) {
        viewModelScope.launch {
            val hosts = repo.observeHosts(scanId).first()
            val obs = repo.observeObservations(scanId).first()
            val findings = repo.observeFindings(scanId).first()
            com.watchdog.app.share.ScanShare.share(
                context,
                com.watchdog.app.share.ScanShare.reportText(hosts, obs, findings),
            )
        }
    }

    // --- lifecycle / nav -------------------------------------------------------

    fun cancel() { ScanForegroundService.cancel(getApplication()) }

    fun startOver() {
        // Stop any running/pending scan job so discovery or a scan doesn't keep
        // running in the background after the user leaves the flow.
        val s = runState.value
        if (s.running || s.awaitingHostPick) ScanForegroundService.cancel(getApplication())
        ScanStateHolder.update { ScanRunState() }
        _selectedDevices.value = emptySet()
        _selectedHost.value = null
        _currentScanId.value = null
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
