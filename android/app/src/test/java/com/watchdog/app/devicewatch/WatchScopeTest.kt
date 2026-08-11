package com.watchdog.app.devicewatch

import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WatchScopeTest {

    private fun net(ssid: String?, cidr: Cidr?, isWifi: Boolean = true) =
        NetworkInfo(ssid = ssid, cidr = cidr, localIp = null, gatewayIp = null, isWifi = isWifi)

    @Test
    fun `scope key matches NetScan's network id format`() {
        val cidr = Cidr.of("192.168.1.37", 24)
        // Same shape as ScanRepository.startScan: "ssid|networkAddr/prefix" (raw long addr).
        val expected = "Home|${cidr.networkAddr}/24"
        assertEquals(expected, WatchScope.of(net("Home", cidr)))
    }

    @Test
    fun `scope key falls back to net when ssid is null`() {
        val cidr = Cidr.of("10.0.0.5", 8)
        assertEquals("net|${cidr.networkAddr}/8", WatchScope.of(net(null, cidr)))
    }

    @Test
    fun `scope key is null without a subnet`() {
        assertNull(WatchScope.of(net("Home", null)))
    }

    @Test
    fun `same subnet different host yields the same scope`() {
        val a = WatchScope.of(net("Home", Cidr.of("192.168.1.10", 24)))
        val b = WatchScope.of(net("Home", Cidr.of("192.168.1.200", 24)))
        assertEquals(a, b)
    }

    @Test
    fun `label prefers ssid then dotted cidr`() {
        assertEquals("Home", WatchScope.label(net("Home", Cidr.of("192.168.1.1", 24))))
        assertEquals("192.168.1.0/24", WatchScope.label(net(null, Cidr.of("192.168.1.1", 24))))
        assertEquals("network", WatchScope.label(net(null, null)))
    }
}
