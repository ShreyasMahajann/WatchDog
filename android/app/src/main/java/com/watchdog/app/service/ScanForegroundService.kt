package com.watchdog.app.service

import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.scan.ScanScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Runs a scan as a foreground service (connectedDevice type) so long scans keep
 * going while the UI is backgrounded, with a live progress notification and a
 * completion notification. Started + bindable-free: the UI drives it via
 * startService intents and observes ScanStateHolder directly.
 */
class ScanForegroundService : LifecycleService() {

    private lateinit var controller: ScanController
    private lateinit var notifications: ScanNotifications
    private var watching = false

    override fun onCreate() {
        super.onCreate()
        notifications = ScanNotifications(this)
        notifications.ensureChannel()
        controller = ScanController(applicationContext, lifecycleScope)
        startForegroundNow()
        watchStateForCompletion()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        startForegroundNow()
        val config = configFrom(intent)
        when (intent?.action) {
            ACTION_DISCOVER -> controller.startDiscovery(config)
            ACTION_STOP_DISCOVER -> controller.stopDiscovery()
            ACTION_SCAN_HOSTS -> intent.getStringArrayListExtra(EXTRA_HOSTS)?.let { controller.scanHosts(it, config) }
            // Don't stopSelf() here: that would tear down the scope before the
            // cancellation cleanup runs. cancel() marks the run finished, and
            // watchStateForCompletion() then stops the service cleanly.
            ACTION_CANCEL -> controller.cancel()
        }
        return START_NOT_STICKY
    }

    private fun startForegroundNow() {
        val notif = notifications.progress(ScanStateHolder.current())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                ScanNotifications.PROGRESS_ID,
                notif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(ScanNotifications.PROGRESS_ID, notif)
        }
    }

    private fun watchStateForCompletion() {
        if (watching) return
        watching = true
        lifecycleScope.launch {
            ScanStateHolder.state.collect { state ->
                if (state.running && !state.finished) {
                    notifications.progress(state).also { notif ->
                        getSystemService(android.app.NotificationManager::class.java)
                            .notify(ScanNotifications.PROGRESS_ID, notif)
                    }
                } else if (state.finished) {
                    notifications.complete(state)
                    stopForegroundCompat()
                    stopSelf()
                }
            }
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun configFrom(intent: Intent?): ScanConfig {
        val scope = intent?.getStringExtra(EXTRA_SCOPE)?.let { runCatching { ScanScope.valueOf(it) }.getOrNull() }
            ?: ScanScope.WHOLE_NETWORK
        val depth = intent?.getStringExtra(EXTRA_DEPTH)?.let { runCatching { ScanDepth.valueOf(it) }.getOrNull() }
            ?: ScanDepth.TOP_1000
        return ScanConfig(scope = scope, depth = depth)
    }

    companion object {
        const val ACTION_DISCOVER = "com.watchdog.app.DISCOVER"
        const val ACTION_STOP_DISCOVER = "com.watchdog.app.STOP_DISCOVER"
        const val ACTION_SCAN_HOSTS = "com.watchdog.app.SCAN_HOSTS"
        const val ACTION_CANCEL = "com.watchdog.app.CANCEL"
        const val EXTRA_HOSTS = "hosts"
        const val EXTRA_SCOPE = "scope"
        const val EXTRA_DEPTH = "depth"

        private fun base(context: Context, action: String, depth: ScanDepth, scope: ScanScope) =
            Intent(context, ScanForegroundService::class.java).apply {
                this.action = action
                putExtra(EXTRA_DEPTH, depth.name)
                putExtra(EXTRA_SCOPE, scope.name)
            }

        fun startDiscovery(context: Context, depth: ScanDepth) =
            context.startForegroundService(base(context, ACTION_DISCOVER, depth, ScanScope.SINGLE_HOST))

        fun stopDiscovery(context: Context) =
            context.startForegroundService(base(context, ACTION_STOP_DISCOVER, ScanDepth.TOP_1000, ScanScope.SINGLE_HOST))

        fun scanHosts(context: Context, ips: List<String>, depth: ScanDepth) =
            context.startForegroundService(
                base(context, ACTION_SCAN_HOSTS, depth, ScanScope.SINGLE_HOST)
                    .putStringArrayListExtra(EXTRA_HOSTS, ArrayList(ips)),
            )

        fun cancel(context: Context) =
            context.startForegroundService(base(context, ACTION_CANCEL, ScanDepth.TOP_1000, ScanScope.SINGLE_HOST))
    }
}
