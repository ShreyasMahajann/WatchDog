package com.watchdog.app.net

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.wifi.WifiManager
import androidx.core.content.ContextCompat
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.callbackFlow
import java.net.Inet4Address

/**
 * Derives the current subnet from ConnectivityManager/LinkProperties (the
 * reliable path — not the deprecated WifiManager.getDhcpInfo()). SSID is
 * best-effort: it needs location/nearby-wifi permission and may read
 * "<unknown ssid>" without it, in which case we surface null rather than lie.
 */
class AndroidNetworkContext(private val appContext: Context) : NetworkContext {

    override fun current(): NetworkInfo? {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val active = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(active)
        val isWifi = caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true
        val lp: LinkProperties = cm.getLinkProperties(active) ?: return null

        val v4 = lp.linkAddresses.firstOrNull { it.address is Inet4Address } ?: return null
        val localIp = v4.address.hostAddress
        val cidr = localIp?.let { Cidr.of(it, v4.prefixLength) }

        val gateway = lp.routes
            .firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
            ?.gateway?.hostAddress

        return NetworkInfo(
            ssid = if (isWifi) currentSsid() else null,
            cidr = cidr,
            localIp = localIp,
            gatewayIp = gateway,
            isWifi = isWifi,
        )
    }

    override fun changes(): Flow<Unit> = callbackFlow {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: run { close(); return@callbackFlow }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { trySend(Unit) }
            override fun onLost(network: Network) { trySend(Unit) }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) { trySend(Unit) }
            override fun onCapabilitiesChanged(
                network: Network,
                caps: android.net.NetworkCapabilities,
            ) { trySend(Unit) }
        }
        cm.registerDefaultNetworkCallback(callback)
        awaitClose { cm.unregisterNetworkCallback(callback) }
    }.conflate()

    @Suppress("DEPRECATION")
    private fun currentSsid(): String? {
        val hasLocation = ContextCompat.checkSelfPermission(
            appContext, Manifest.permission.ACCESS_FINE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED
        val hasNearby = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                appContext, Manifest.permission.NEARBY_WIFI_DEVICES,
            ) == PackageManager.PERMISSION_GRANTED
        if (!hasLocation && !hasNearby) return null

        val wifi = appContext.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return null
        val raw = wifi.connectionInfo?.ssid ?: return null
        val ssid = raw.trim('"')
        return if (ssid.isBlank() || ssid == "<unknown ssid>" || ssid == "0x") null else ssid
    }
}
