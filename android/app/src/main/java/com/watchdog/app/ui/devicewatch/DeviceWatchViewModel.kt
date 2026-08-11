package com.watchdog.app.ui.devicewatch

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.watchdog.app.devicewatch.DeviceWatchScanner
import com.watchdog.app.devicewatch.WatchScope
import com.watchdog.app.devicewatch.WatchOutcome
import com.watchdog.app.devicewatch.data.DeviceWatchDatabase
import com.watchdog.app.devicewatch.data.DeviceWatchRepository
import com.watchdog.app.devicewatch.data.WatchedDeviceEntity
import com.watchdog.app.net.AndroidNetworkContext
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.discovery.MdnsDiscoverer
import com.watchdog.app.scan.discovery.ReachabilityDiscoverer
import com.watchdog.app.scan.discovery.TcpProbeDiscoverer
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Owns Device Watch's state: the current network, the per-network device inventory, and the on-demand
 * scan action. Everything is real — a scan actually sweeps the LAN via [DeviceWatchScanner] and the
 * inventory is persisted in its own Room database.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DeviceWatchViewModel(app: Application) : AndroidViewModel(app) {

    private val networkContext = AndroidNetworkContext(app)
    private val repo = DeviceWatchRepository(DeviceWatchDatabase.get(app).dao())
    private val engine = ScanEngine(
        discoverers = listOf(
            TcpProbeDiscoverer(),
            ReachabilityDiscoverer(),
            MdnsDiscoverer(app),
        ),
    )
    private val scanner = DeviceWatchScanner(networkContext, engine, repo)

    private val _network = MutableStateFlow<NetworkInfo?>(null)
    val network: StateFlow<NetworkInfo?> = _network.asStateFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()
    fun consumeMessage() { _message.value = null }

    private val _selectedId = MutableStateFlow<Long?>(null)
    val selectedId: StateFlow<Long?> = _selectedId.asStateFlow()
    fun selectDevice(id: Long) { _selectedId.value = id }

    /** The inventory for whatever network the phone is on now; empty when off Wi-Fi. */
    val devices: StateFlow<List<WatchedDeviceEntity>> =
        _network.flatMapLatest { net ->
            val scope = net?.let { WatchScope.of(it) }
            if (scope == null) flowOf(emptyList()) else repo.observeScope(scope)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    init { refreshNetwork() }

    fun refreshNetwork() { _network.value = networkContext.current() }

    /** Sweep the current LAN and diff it against the saved baseline. One run at a time. */
    fun scanNow() {
        if (_scanning.value) return
        viewModelScope.launch {
            _scanning.value = true
            refreshNetwork()
            _message.value = when (val r = scanner.scan()) {
                WatchOutcome.NoNetwork ->
                    "Join a Wi-Fi network first — Device Watch needs a LAN to sweep."
                is WatchOutcome.Scanned -> buildString {
                    append("${r.present} device(s) present")
                    if (r.newCount > 0) append(" · ${r.newCount} new")
                    if (r.offline > 0) append(" · ${r.offline} offline")
                }
            }
            _scanning.value = false
        }
    }

    fun trust(id: Long) { viewModelScope.launch { repo.setTrusted(id, true) } }
    fun untrust(id: Long) { viewModelScope.launch { repo.setTrusted(id, false) } }
    fun rename(id: Long, name: String) { viewModelScope.launch { repo.rename(id, name) } }

    fun forget(id: Long) {
        viewModelScope.launch {
            repo.forget(id)
            if (_selectedId.value == id) _selectedId.value = null
        }
    }
}
