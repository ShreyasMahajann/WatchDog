package com.watchdog.app.net

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * Lists nearby Wi-Fi access points for context only. Honest about the platform:
 * these are just beacons — you can host-scan ONLY the network you are joined to,
 * never a nearby SSID you haven't joined. Android gates scan results behind
 * NEARBY_WIFI_DEVICES / ACCESS_FINE_LOCATION *and* location services being on,
 * and getScanResults() is throttled — so this reports precisely why the list is
 * empty rather than silently showing nothing.
 */
class WifiScanner(private val appContext: Context) {

    data class NearbyAp(
        val ssid: String,
        val bssid: String,
        val signalLevel: Int, // 0..4
        val connected: Boolean,
    )

    enum class Status {
        OK, // results returned
        NO_PERMISSION, // nearby-wifi / location permission not granted
        LOCATION_OFF, // permission ok but location services toggle is off
        EMPTY, // everything ok, but no cached results yet (try Rescan)
    }

    data class Result(val status: Status, val aps: List<NearbyAp>)

    fun hasPermission(): Boolean {
        val nearby = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(appContext, Manifest.permission.NEARBY_WIFI_DEVICES) ==
            PackageManager.PERMISSION_GRANTED
        val location = ContextCompat.checkSelfPermission(appContext, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        return nearby || location
    }

    fun locationEnabled(): Boolean {
        val lm = appContext.getSystemService(Context.LOCATION_SERVICE) as? LocationManager ?: return false
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            lm.isLocationEnabled
        } else {
            @Suppress("DEPRECATION")
            lm.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
        }
    }

    @Suppress("DEPRECATION")
    fun scan(): Result {
        if (!hasPermission()) return Result(Status.NO_PERMISSION, emptyList())
        if (!locationEnabled()) return Result(Status.LOCATION_OFF, emptyList())

        val wifi = appContext.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return Result(Status.EMPTY, emptyList())
        return try {
            // Kick a fresh scan (throttled by the OS) then read cached results.
            runCatching { wifi.startScan() }
            val connectedBssid = wifi.connectionInfo?.bssid
            val aps = wifi.scanResults
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
            Result(if (aps.isEmpty()) Status.EMPTY else Status.OK, aps)
        } catch (e: SecurityException) {
            Result(Status.NO_PERMISSION, emptyList())
        } catch (e: Exception) {
            Result(Status.EMPTY, emptyList())
        }
    }
}
