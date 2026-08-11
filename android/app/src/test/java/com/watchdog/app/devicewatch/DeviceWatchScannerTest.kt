package com.watchdog.app.devicewatch

import com.watchdog.app.devicewatch.data.DeviceWatchDao
import com.watchdog.app.devicewatch.data.DeviceWatchRepository
import com.watchdog.app.devicewatch.data.WatchedDeviceEntity
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

    // --- fakes ----------------------------------------------------------------

    private class FakeNetworkContext(private val info: NetworkInfo?) : NetworkContext {
        override fun current(): NetworkInfo? = info
        override fun changes(): Flow<Unit> = flowOf()
    }

    private class FakeDiscoverer(private val hosts: List<DiscoveredHost>) : HostDiscoverer {
        override val source = "fake"
        override fun discover(cidr: Cidr, config: ScanConfig): Flow<DiscoveredHost> = hosts.asFlow()
    }

    /** In-memory stand-in for the Room DAO, mirroring the semantics the scanner relies on. */
    private class FakeDao : DeviceWatchDao {
        val rows = mutableListOf<WatchedDeviceEntity>()
        private var nextId = 1L

        override fun observeScope(scopeKey: String) = flowOf(rows.filter { it.scopeKey == scopeKey })
        override suspend fun devicesInScope(scopeKey: String) = rows.filter { it.scopeKey == scopeKey }
        override fun observeById(id: Long) = flowOf(rows.firstOrNull { it.id == id })

        override suspend fun insertAll(rows: List<WatchedDeviceEntity>) {
            for (r in rows) {
                val clash = this.rows.any { it.scopeKey == r.scopeKey && it.ip == r.ip }
                if (clash) continue // OnConflictStrategy.IGNORE
                this.rows += r.copy(id = nextId++)
            }
        }

        override suspend fun updateAll(rows: List<WatchedDeviceEntity>) {
            for (r in rows) {
                val i = this.rows.indexOfFirst { it.id == r.id }
                if (i >= 0) this.rows[i] = r
            }
        }

        override suspend fun markAbsent(scopeKey: String, seenIps: Collection<String>) {
            for (i in rows.indices) {
                val r = rows[i]
                if (r.scopeKey == scopeKey && r.ip !in seenIps) rows[i] = r.copy(present = false)
            }
        }

        override suspend fun markAllAbsent(scopeKey: String) {
            for (i in rows.indices) {
                if (rows[i].scopeKey == scopeKey) rows[i] = rows[i].copy(present = false)
            }
        }

        override suspend fun setTrusted(id: Long, trusted: Boolean) {
            val i = rows.indexOfFirst { it.id == id }
            if (i >= 0) rows[i] = rows[i].copy(trusted = trusted)
        }

        override suspend fun setLabel(id: Long, label: String?) {
            val i = rows.indexOfFirst { it.id == id }
            if (i >= 0) rows[i] = rows[i].copy(label = label)
        }

        override suspend fun deleteById(id: Long) { rows.removeAll { it.id == id } }
    }

    private fun wifi(cidr: Cidr? = Cidr.of("192.168.1.10", 24)) =
        NetworkInfo(ssid = "Home", cidr = cidr, localIp = "192.168.1.10", gatewayIp = "192.168.1.1", isWifi = true)

    private fun scanner(net: NetworkInfo?, hosts: List<DiscoveredHost>, dao: FakeDao, now: Long) =
        DeviceWatchScanner(
            networkContext = FakeNetworkContext(net),
            engine = ScanEngine(discoverers = listOf(FakeDiscoverer(hosts))),
            repo = DeviceWatchRepository(dao),
            now = { now },
        )

    private fun host(ip: String) = DiscoveredHost(ip = ip, source = "fake")

    // --- tests ----------------------------------------------------------------

    @Test
    fun `no wifi returns NoNetwork and writes nothing`() = runTest {
        val dao = FakeDao()
        val notWifi = wifi().copy(isWifi = false)
        val outcome = scanner(notWifi, listOf(host("192.168.1.2")), dao, now = 1).scan()
        assertEquals(WatchOutcome.NoNetwork, outcome)
        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun `no subnet returns NoNetwork`() = runTest {
        val dao = FakeDao()
        val outcome = scanner(wifi(cidr = null), emptyList(), dao, now = 1).scan()
        assertEquals(WatchOutcome.NoNetwork, outcome)
    }

    @Test
    fun `first scan persists all devices as present and new`() = runTest {
        val dao = FakeDao()
        val outcome = scanner(wifi(), listOf(host("192.168.1.2"), host("192.168.1.3")), dao, now = 10).scan()
        assertEquals(WatchOutcome.Scanned(present = 2, newCount = 2, offline = 0), outcome)
        assertEquals(2, dao.rows.size)
        assertTrue(dao.rows.all { it.present && !it.trusted })
    }

    @Test
    fun `second scan flips a dropped device offline without deleting it`() = runTest {
        val dao = FakeDao()
        val net = wifi()
        scanner(net, listOf(host("192.168.1.2"), host("192.168.1.3")), dao, now = 10).scan()
        // 192.168.1.3 gone; 192.168.1.9 new.
        val outcome = scanner(net, listOf(host("192.168.1.2"), host("192.168.1.9")), dao, now = 20).scan()

        assertEquals(WatchOutcome.Scanned(present = 2, newCount = 1, offline = 1), outcome)
        assertEquals(3, dao.rows.size) // nothing deleted
        val dropped = dao.rows.single { it.ip == "192.168.1.3" }
        assertFalse(dropped.present)
        val added = dao.rows.single { it.ip == "192.168.1.9" }
        assertTrue(added.present && !added.trusted)
    }

    @Test
    fun `trust survives a rescan`() = runTest {
        val dao = FakeDao()
        val net = wifi()
        scanner(net, listOf(host("192.168.1.2")), dao, now = 10).scan()
        DeviceWatchRepository(dao).setTrusted(dao.rows.single().id, true)

        val outcome = scanner(net, listOf(host("192.168.1.2")), dao, now = 20).scan()
        assertEquals(WatchOutcome.Scanned(present = 1, newCount = 0, offline = 0), outcome)
        assertTrue(dao.rows.single().trusted)
        assertEquals(20L, dao.rows.single().lastSeen)
    }
}
