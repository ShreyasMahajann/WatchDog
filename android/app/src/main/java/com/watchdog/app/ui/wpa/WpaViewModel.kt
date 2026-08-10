package com.watchdog.app.ui.wpa

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbManager
import android.net.Uri
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.watchdog.app.wpa.creds.WpaSecCredentials
import com.watchdog.app.wpa.data.CaptureEntity
import com.watchdog.app.wpa.data.WpaDatabase
import com.watchdog.app.wpa.data.WpaRepository
import com.watchdog.app.wpa.device.Capability
import com.watchdog.app.wpa.diagnostics.DiagnosticsCollector
import com.watchdog.app.wpa.diagnostics.DiagnosticsReport
import com.watchdog.app.wpa.capture.CaptureParams
import com.watchdog.app.wpa.capture.CaptureResult
import com.watchdog.app.wpa.capture.RootCaptureEngine
import com.watchdog.app.wpa.storage.CaptureStore
import com.watchdog.app.wpa.tracking.RefreshOutcome
import com.watchdog.app.wpa.tracking.SubmissionTracker
import com.watchdog.app.wpa.tracking.SubmitOutcome
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Owns the WPA feature's state: device diagnostics, the capture library, the WPA-sec key, and
 * submission/tracking. All actions are real — importing validates a genuine pcap, submitting hits
 * WPA-sec, and status comes from the potfile. Nothing here fabricates a capture or a result.
 */
class WpaViewModel(app: Application) : AndroidViewModel(app) {

    private val collector = DiagnosticsCollector(app)
    private val store = CaptureStore(app)
    private val repo = WpaRepository(WpaDatabase.get(app).dao())
    private val creds = WpaSecCredentials(app)
    private val tracker = SubmissionTracker(app)
    private val captureEngine = RootCaptureEngine(app)

    // --- diagnostics ----------------------------------------------------------

    private val _report = MutableStateFlow<DiagnosticsReport?>(null)
    val report = _report.asStateFlow()

    private val _loading = MutableStateFlow(false)
    val loading = _loading.asStateFlow()

    // --- capture library ------------------------------------------------------

    val captures: StateFlow<List<CaptureEntity>> =
        repo.observeAll().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()

    private val _selectedCaptureId = MutableStateFlow<Long?>(null)
    val selectedCaptureId = _selectedCaptureId.asStateFlow()
    fun selectCapture(id: Long) { _selectedCaptureId.value = id }

    /** Candidate interfaces for on-device capture (monitor-looking first). */
    fun captureInterfaces(): List<String> {
        val ifaces = report.value?.interfaces.orEmpty()
        return (ifaces.filter { it.looksMonitor } + ifaces.filter { it.name.startsWith("wlan") })
            .map { it.name }.distinct()
    }

    private val _message = MutableStateFlow<String?>(null)
    val message = _message.asStateFlow()
    fun consumeMessage() { _message.value = null }

    // --- WPA-sec key ----------------------------------------------------------

    private val _keyConfigured = MutableStateFlow(creds.isConfigured())
    val keyConfigured = _keyConfigured.asStateFlow()

    /** Whether on-device capture is actually possible, derived from the live capability model. */
    val captureSupported: StateFlow<Boolean> =
        report.map { it?.capability?.handshakeCapturePossible is Capability.Supported }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    fun captureBlockedReason(): String? =
        (report.value?.capability?.handshakeCapturePossible as? Capability.Unsupported)?.reason
            ?: (report.value?.capability?.handshakeCapturePossible as? Capability.Unknown)?.reason

    // --- USB attach/detach → diagnostics refresh ------------------------------

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) = refresh(activeRootCheck = false)
    }

    init {
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        ContextCompat.registerReceiver(app, usbReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        refresh(activeRootCheck = false)
    }

    fun refresh(activeRootCheck: Boolean) {
        viewModelScope.launch {
            _loading.value = true
            _report.value = collector.collect(activeRootCheck)
            _loading.value = false
        }
    }

    fun testRootAccess() = refresh(activeRootCheck = true)

    // --- capture library actions ----------------------------------------------

    fun importCapture(uri: Uri) {
        viewModelScope.launch {
            _busy.value = true
            try {
                val imported = store.importFromUri(uri)
                val saved = repo.saveCapture(imported, source = "IMPORT")
                val net = imported.analysis.primary
                _message.value = when {
                    imported.analysis.hasValidHandshake ->
                        "Imported: ${net?.ssid ?: net?.bssid ?: "capture"} — valid handshake ✓"
                    else ->
                        "Imported ${saved.fileName}, but no valid WPA handshake was found in it."
                }
            } catch (e: Exception) {
                _message.value = "Import failed: ${e.message ?: "not a valid capture file"}"
            } finally {
                _busy.value = false
            }
        }
    }

    fun submit(id: Long) {
        viewModelScope.launch {
            _busy.value = true
            _message.value = when (val r = tracker.submit(id)) {
                SubmitOutcome.Submitted -> "Submitted to WPA-sec. Use Refresh to check for a result."
                SubmitOutcome.NoKey -> "Set your WPA-sec key first (WPA-sec key screen)."
                SubmitOutcome.AlreadySubmitted -> "Already submitted — not re-uploading."
                SubmitOutcome.NotFound -> "Capture not found."
                is SubmitOutcome.Failed -> "Submit failed: ${r.detail}"
            }
            _busy.value = false
        }
    }

    fun refreshResults() {
        viewModelScope.launch {
            _busy.value = true
            _message.value = when (val r = tracker.refresh()) {
                is RefreshOutcome.Updated ->
                    if (r.newlyCracked > 0) "${r.newlyCracked} password(s) found!"
                    else "Checked ${r.checked} submission(s) — no new results yet."
                RefreshOutcome.NoKey -> "Set your WPA-sec key first."
                RefreshOutcome.InvalidKey -> "WPA-sec rejected the key. Check it on the key screen."
                is RefreshOutcome.NetworkError -> "Couldn't reach WPA-sec: ${r.detail}"
            }
            _busy.value = false
        }
    }

    fun deleteCapture(entity: CaptureEntity) {
        viewModelScope.launch { repo.delete(entity, store) }
    }

    /** On-device capture. Only reachable when [captureSupported] is true; the engine re-checks root
     *  and fails cleanly if the device can't actually do it. */
    fun startCapture(iface: String, channel: Int?, durationSec: Int) {
        viewModelScope.launch {
            _busy.value = true
            _message.value = "Capturing on $iface for ${durationSec}s…"
            val params = CaptureParams(
                iface = iface,
                monitorIface = iface,
                channel = channel,
                durationSec = durationSec,
                label = System.currentTimeMillis().toString(),
            )
            when (val r = captureEngine.capture(params)) {
                is CaptureResult.Success -> {
                    val file = java.io.File(r.filePath)
                    val imported = store.importBytes(file.readBytes(), file.name)
                    repo.saveCapture(imported, source = "CAPTURE")
                    if (file.name != java.io.File(imported.filePath).name) store.delete(r.filePath)
                    _message.value = if (r.analysis.hasValidHandshake) {
                        "Captured a valid handshake ✓"
                    } else {
                        "Capture saved, but no valid handshake yet — try again near an active client."
                    }
                }
                is CaptureResult.Failure -> _message.value = "Capture failed: ${r.reason}"
            }
            _busy.value = false
        }
    }

    // --- key management -------------------------------------------------------

    fun saveKey(key: String) {
        val trimmed = key.trim()
        if (trimmed.isEmpty()) { _message.value = "Key was empty — nothing saved."; return }
        creds.setKey(trimmed)
        _keyConfigured.value = true
        _message.value = if (WpaSecCredentials.looksValid(trimmed)) {
            "WPA-sec key saved."
        } else {
            "Key saved, but it doesn't look like a 32-hex WPA-sec key — double-check it."
        }
    }

    fun clearKey() {
        creds.clear()
        _keyConfigured.value = false
        _message.value = "WPA-sec key removed."
    }

    override fun onCleared() {
        runCatching { getApplication<Application>().unregisterReceiver(usbReceiver) }
    }
}
