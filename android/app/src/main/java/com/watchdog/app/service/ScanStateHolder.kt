package com.watchdog.app.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Process-singleton live scan state. Lives outside any ViewModel so a running
 * scan survives config changes and UI death (the foreground service keeps the
 * process alive). The UI collects [state]; the controller mutates it.
 */
object ScanStateHolder {
    private val _state = MutableStateFlow(ScanRunState())
    val state: StateFlow<ScanRunState> = _state.asStateFlow()

    fun reset(scanId: Long?, scope: com.watchdog.app.scan.ScanScope) {
        _state.value = ScanRunState(scanId = scanId, scope = scope, running = true)
    }

    fun update(block: (ScanRunState) -> ScanRunState) = _state.update(block)

    fun current(): ScanRunState = _state.value
}
