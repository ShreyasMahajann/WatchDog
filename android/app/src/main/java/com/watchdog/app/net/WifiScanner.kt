package com.watchdog.app.net

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * Lists nearby Wi-Fi access points for context only. Honest about the platform:
 * these are just beacons — you can host-scan ONLY the network you are joined to,
 * never a nearby SSID you haven't joined. Results are gated behind
 * NEARBY_WIFI_DEVICES / ACCESS_FINE_LOCATION with location services on, and
 * getScanResults() is throttled, so this returns whatever the last scan cached.
 */
class WifiScanner(private val appContext: Context) {

    data class NearbyAp(
        val ssid: String,
        val bssid: String,
        val signalLevel: Int, // 0..4
        val connected: Boolean,
    )

    fun hasPermission(): Boolean {
        val nearby = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(appContext, Manifest.permission.NEARBY_WIFI_DEVICES) ==
            PackageManager.PERMISSION_GRANTED
        val location = ContextCompat.checkSelfPermission(appContext, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        return nearby || location
    }

    @Suppress("DEPRECATION")
    fun scan(): List<NearbyAp> {
        if (!hasPermission()) return emptyList()
        val wifi = appContext.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return emptyList()
        return try {
            val connectedBssid = wifi.connectionInfo?.bssid
            wifi.scanResults
                .filter { it.SSID.isNotBlank() }
                .distinctBy { it.BSSID }
                .sortedByDescending { it.level }
                .map { r ->
                    NearbyAp(
                        ssid = r.SSID,
                        bssid = r.BSSID,
                        signalLevel = WifiManager.calculateSignalLevel(r.level, 5),
                        connected = r.BSSID == connectedBssid,
                    )
                }
        } catch (e: SecurityException) {
            emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
