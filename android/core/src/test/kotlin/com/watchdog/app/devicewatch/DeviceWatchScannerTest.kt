package com.watchdog.app.devicewatch

import com.watchdog.app.net.Cidr
import com.watchdog.app.net.NetworkContext
import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.ScanEngine
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.discovery.HostDiscoverer
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceWatchScannerTest {

    private class FakeNetworkContext(private val info: NetworkInfo?) : NetworkContext {
        override fun current(): NetworkInfo? = info
        override fun changes(): Flow<Unit> = flowOf()
    }

    private class FakeDiscoverer(private val hosts: List<DiscoveredHost>) : HostDiscoverer {
        override val source = "fake"
        override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = hosts.asFlow()
    }

    /** In-memory [DeviceWatchStore], mirroring the semantics the scanner relies on. */
    private class FakeStore : DeviceWatchStore {
        val rows = mutableListOf<WatchedDevice>()
        private var nextId = 1L

        override suspend fun devicesInScope(scopeKey: String): List<WatchedDevice> =
            rows.filter { it.scopeKey == scopeKey }

        override suspend fun applyScan(
            toInsert: List<WatchedDevice>,
            toUpdate: List<WatchedDevice>,
            scopeKey: String,
            seenIps: Collection<String>,
        ) {
            for (r in toInsert) {
                val clash = rows.any { it.scopeKey == r.scopeKey && it.ip == r.ip }
                if (!clash) rows += r.copy(id = nextId++)
            }
            for (r in toUpdate) {
                val i = rows.indexOfFirst { it.id == r.id }
                if (i >= 0) rows[i] = r
            }
            if (seenIps.isEmpty()) {
                for (i in rows.indices) if (rows[i].scopeKey == scopeKey) rows[i] = rows[i].copy(present = false)
            } else {
                for (i in rows.indices) {
                    val r = rows[i]
                    if (r.scopeKey == scopeKey && r.ip !in seenIps) rows[i] = r.copy(present = false)
                }
            }
        }

        fun setTrusted(id: Long, trusted: Boolean) {
            val i = rows.indexOfFirst { it.id == id }
            if (i >= 0) rows[i] = rows[i].copy(trusted = trusted)
        }
    }

    private fun wifi(cidr: Cidr? = Cidr.of("192.168.1.10", 24)) =
        NetworkInfo(ssid = "Home", cidr = cidr, localIp = "192.168.1.10", gatewayIp = "192.168.1.1", isWifi = true)

    private fun scanner(net: NetworkInfo?, hosts: List<DiscoveredHost>, store: FakeStore, now: Long) =
        DeviceWatchScanner(
            networkContext = FakeNetworkContext(net),
            engine = ScanEngine(discoverers = listOf(FakeDiscoverer(hosts))),
            repo = store,
            now = { now },
        )

    private fun host(ip: String) = DiscoveredHost(ip = ip, source = "fake")

    @Test
    fun `no wifi returns NoNetwork and writes nothing`() = runTest {
        val store = FakeStore()
        val notWifi = wifi().copy(isWifi = false)
        val outcome = scanner(notWifi, listOf(host("192.168.1.2")), store, now = 1).scan()
        assertEquals(WatchOutcome.NoNetwork, outcome)
        assertTrue(store.rows.isEmpty())
    }

    @Test
    fun `no subnet returns NoNetwork`() = runTest {
        val store = FakeStore()
        val outcome = scanner(wifi(cidr = null), emptyList(), store, now = 1).scan()
        assertEquals(WatchOutcome.NoNetwork, outcome)
    }

    @Test
    fun `first scan persists all devices as present and new`() = runTest {
        val store = FakeStore()
        val outcome = scanner(wifi(), listOf(host("192.168.1.2"), host("192.168.1.3")), store, now = 10).scan()
        assertEquals(WatchOutcome.Scanned(present = 3, newCount = 3, offline = 0), outcome)
        assertEquals(3, store.rows.size)
        assertTrue(store.rows.all { it.present && !it.trusted })
    }

    @Test
    fun `empty discovery still seeds the known-live gateway`() = runTest {
        val store = FakeStore()
        val outcome = scanner(wifi(), emptyList(), store, now = 10).scan()
        assertEquals(WatchOutcome.Scanned(present = 1, newCount = 1, offline = 0), outcome)
        assertEquals("192.168.1.1", store.rows.single().ip)
        assertEquals("gateway", store.rows.single().hostname)
    }

    @Test
    fun `second scan flips a dropped device offline without deleting it`() = runTest {
        val store = FakeStore()
        val net = wifi()
        scanner(net, listOf(host("192.168.1.2"), host("192.168.1.3")), store, now = 10).scan()
        val outcome = scanner(net, listOf(host("192.168.1.2"), host("192.168.1.9")), store, now = 20).scan()
        assertEquals(WatchOutcome.Scanned(present = 3, newCount = 1, offline = 1), outcome)
        assertEquals(4, store.rows.size)
        val dropped = store.rows.single { it.ip == "192.168.1.3" }
        assertFalse(dropped.present)
        val added = store.rows.single { it.ip == "192.168.1.9" }
        assertTrue(added.present && !added.trusted)
    }

    @Test
    fun `trust survives a rescan`() = runTest {
        val store = FakeStore()
        val net = wifi()
        scanner(net, listOf(host("192.168.1.2")), store, now = 10).scan()
        val watched = store.rows.single { it.ip == "192.168.1.2" }
        store.setTrusted(watched.id, true)
        val outcome = scanner(net, listOf(host("192.168.1.2")), store, now = 20).scan()
        assertEquals(WatchOutcome.Scanned(present = 2, newCount = 0, offline = 0), outcome)
        val refreshed = store.rows.single { it.ip == "192.168.1.2" }
        assertTrue(refreshed.trusted)
        assertEquals(20L, refreshed.lastSeen)
    }
}
