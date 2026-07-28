package com.watchdog.app.net

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

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
        UNAVAILABLE, // Wi-Fi service missing or a scan error unrelated to the above
    }

    data class Result(val status: Status, val aps: List<NearbyAp>)

    // getScanResults() is gated on location access even where NEARBY_WIFI_DEVICES
    // is held (enforced by many OEM builds), so FINE_LOCATION is the permission
    // that actually decides whether we can read scan results.
    fun hasPermission(): Boolean =
        ContextCompat.checkSelfPermission(appContext, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

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
        // Scan results count as location data — getScanResults() throws without
        // the location toggle on, so surface that as an actionable status.
        if (!locationEnabled()) return Result(Status.LOCATION_OFF, emptyList())

        val wifi = appContext.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return Result(Status.UNAVAILABLE, emptyList())
        return try {
            // Pure read of the last completed scan. Kicking a fresh scan is a
            // separate, rate-limited call (rescan) — starting one on every read
            // exhausts the OS scan quota, after which getScanResults() only
            // returns the sparse association-scan cache (often just the AP you're
            // joined to). Results from freshly-kicked scans arrive via observe().
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
            Result(Status.UNAVAILABLE, emptyList())
        }
    }

    // Android throttles foreground startScan() to ~4 calls / 2 min; blowing past
    // that makes every later scan silently fail. Kicks are spaced to stay under it.
    @Volatile
    private var lastKickAtMs = 0L

    /**
     * Best-effort kick of a fresh OS scan. Rate-limited so bursts of refreshes
     * (launch + network-change + pull-to-refresh) don't exhaust the OS quota and
     * stall real scanning. The OS may still throttle or ignore it.
     */
    @Suppress("DEPRECATION")
    fun rescan() {
        val now = System.currentTimeMillis()
        if (now - lastKickAtMs < MIN_RESCAN_INTERVAL_MS) return
        lastKickAtMs = now
        val wifi = appContext.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        runCatching { wifi?.startScan() }
    }

    /**
     * Emits the current result immediately, then again each time the OS finishes a
     * scan (SCAN_RESULTS_AVAILABLE_ACTION). getScanResults() only reflects the last
     * *completed* scan, so reading it synchronously right after startScan() misses
     * freshly-found networks — this stream delivers them when they actually arrive.
     */
    fun observe(): Flow<Result> = callbackFlow {
        trySend(scan())
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                trySend(scan())
            }
        }
        ContextCompat.registerReceiver(
            appContext,
            receiver,
            IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        rescan()
        awaitClose { runCatching { appContext.unregisterReceiver(receiver) } }
    }

    private companion object {
        // Minimum spacing between OS scan kicks; keeps us under Android's
        // foreground throttle (~4 startScan() calls per 2 minutes).
        const val MIN_RESCAN_INTERVAL_MS = 30_000L
    }
}
