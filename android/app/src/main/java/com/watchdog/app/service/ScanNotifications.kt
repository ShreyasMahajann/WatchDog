package com.watchdog.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.watchdog.app.MainActivity
import com.watchdog.app.R

/** Builds the ongoing-progress and completion notifications for a scan. */
class ScanNotifications(private val context: Context) {

    fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = context.getSystemService(NotificationManager::class.java)
            if (mgr.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "Network scans",
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { description = "Progress and results of watchDog scans" }
                mgr.createNotificationChannel(channel)
            }
        }
    }

    fun progress(state: ScanRunState): Notification {
        val text = when (state.phase) {
            com.watchdog.app.scan.ScanPhase.DISCOVERING ->
                "Discovering hosts… ${state.discoveredHosts.size} found"
            com.watchdog.app.scan.ScanPhase.ENUMERATING,
            com.watchdog.app.scan.ScanPhase.FINGERPRINTING ->
                "Scanning ${state.currentHost ?: ""} (${state.hostsDone}/${state.hostsTotal.coerceAtLeast(1)})"
            com.watchdog.app.scan.ScanPhase.CORRELATING -> "Checking CVE database…"
            com.watchdog.app.scan.ScanPhase.DONE -> "Finishing…"
        }
        val builder = baseBuilder()
            .setContentTitle("watchDog scanning")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openAppIntent())
        if (state.hostsTotal > 0) {
            builder.setProgress(state.hostsTotal, state.hostsDone, false)
        } else {
            builder.setProgress(0, 0, true)
        }
        return builder.build()
    }

    fun complete(state: ScanRunState) {
        val active = state.findings.count { !it.suppressed }
        val text = when {
            state.cancelled -> "Scan cancelled"
            state.failureMessage != null -> "Scan failed: ${state.failureMessage}"
            else -> "$active finding${if (active == 1) "" else "s"} across ${state.discoveredHosts.size} host${if (state.discoveredHosts.size == 1) "" else "s"}"
        }
        val notif = baseBuilder()
            .setContentTitle(if (state.failureMessage != null) "watchDog scan failed" else "Scan complete")
            .setContentText(text)
            .setAutoCancel(true)
            .setOngoing(false)
            .setContentIntent(openAppIntent())
            .build()
        val mgr = context.getSystemService(NotificationManager::class.java)
        mgr.notify(COMPLETE_ID, notif)
    }

    fun cancelCompletion() {
        context.getSystemService(NotificationManager::class.java).cancel(COMPLETE_ID)
    }

    private fun baseBuilder() = NotificationCompat.Builder(context, CHANNEL_ID)
        .setSmallIcon(R.mipmap.ic_launcher)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setCategory(NotificationCompat.CATEGORY_PROGRESS)

    private fun openAppIntent(): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    companion object {
        const val CHANNEL_ID = "watchdog_scans"
        const val PROGRESS_ID = 1001
        const val COMPLETE_ID = 1002
    }
}
