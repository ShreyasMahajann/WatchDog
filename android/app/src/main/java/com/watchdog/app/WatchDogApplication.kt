package com.watchdog.app

import android.app.Application
import com.watchdog.app.service.ScanNotifications

class WatchDogApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Create the notification channel early so the FGS can post immediately.
        ScanNotifications(this).ensureChannel()
    }
}
