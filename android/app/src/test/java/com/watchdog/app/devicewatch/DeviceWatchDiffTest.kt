package com.watchdog.app.devicewatch

import com.watchdog.app.devicewatch.data.WatchedDeviceEntity
import com.watchdog.app.scan.discovery.DiscoveredHost
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceWatchDiffTest {

    private val scope = "Home|123/24"
    private val label = "Home"

    private fun host(ip: String, hostname: String? = null, hints: List<String> = emptyList()) =
        DiscoveredHost(ip = ip, hostname = hostname, source = "fake", serviceHints = hints)

    private fun known(
        id: Long,
        ip: String,
        trusted: Boolean = false,
        hostname: String? = null,
        hints: String = "",
        present: Boolean = true,
        first: Long = 100,
    ) = WatchedDeviceEntity(
        id = id, scopeKey = scope, networkLabel = label, ip = ip, hostname = hostname,
        serviceHints = hints, label = null, trusted = trusted, firstSeen = first, lastSeen = first, present = present,
    )

    @Test
    fun `first scan marks everything present as new`() {
        val d = DeviceWatchDiff.compute(
            existing = emptyList(),
            discovered = listOf(host("192.168.1.2"), host("192.168.1.3")),
            scopeKey = scope, networkLabel = label, now = 1000,
        )
        assertEquals(2, d.toInsert.size)
        assertEquals(0, d.toUpdate.size)
        assertEquals(2, d.newCount)
        assertEquals(2, d.present)
        assertEquals(0, d.offline)
        assertTrue(d.toInsert.all { !it.trusted && it.present && it.firstSeen == 1000L })
    }

    @Test
    fun `a newly-joined host is the only one flagged new`() {
        val d = DeviceWatchDiff.compute(
            existing = listOf(known(1, "192.168.1.2")),
            discovered = listOf(host("192.168.1.2"), host("192.168.1.9")),
            scopeKey = scope, networkLabel = label, now = 2000,
        )
        assertEquals(1, d.newCount)
        assertEquals("192.168.1.9", d.toInsert.single().ip)
        assertEquals(1, d.toUpdate.size)
        assertEquals(2, d.present)
        assertEquals(0, d.offline)
    }

    @Test
    fun `a dropped host goes offline and is not deleted`() {
        val d = DeviceWatchDiff.compute(
            existing = listOf(known(1, "192.168.1.2"), known(2, "192.168.1.3")),
            discovered = listOf(host("192.168.1.2")),
            scopeKey = scope, networkLabel = label, now = 3000,
        )
        assertEquals(0, d.newCount)
        assertEquals(1, d.present)
        assertEquals(1, d.offline) // 192.168.1.3 not seen
        assertEquals(listOf("192.168.1.2"), d.toUpdate.map { it.ip })
    }

    @Test
    fun `a trusted device seen again is never re-flagged as new`() {
        val d = DeviceWatchDiff.compute(
            existing = listOf(known(1, "192.168.1.2", trusted = true)),
            discovered = listOf(host("192.168.1.2")),
            scopeKey = scope, networkLabel = label, now = 4000,
        )
        assertEquals(0, d.newCount)
        assertEquals(0, d.toInsert.size)
        val updated = d.toUpdate.single()
        assertTrue(updated.trusted)
        assertTrue(updated.present)
        assertEquals(4000L, updated.lastSeen)
        assertEquals(100L, updated.firstSeen) // firstSeen preserved
    }

    @Test
    fun `refresh keeps a known hostname when discovery reports none`() {
        val d = DeviceWatchDiff.compute(
            existing = listOf(known(1, "192.168.1.2", hostname = "nas.local", hints = "_smb._tcp")),
            discovered = listOf(host("192.168.1.2", hostname = null, hints = emptyList())),
            scopeKey = scope, networkLabel = label, now = 5000,
        )
        val updated = d.toUpdate.single()
        assertEquals("nas.local", updated.hostname)
        assertEquals("_smb._tcp", updated.serviceHints)
    }

    @Test
    fun `duplicate discovered ips are collapsed`() {
        val d = DeviceWatchDiff.compute(
            existing = emptyList(),
            discovered = listOf(host("192.168.1.2"), host("192.168.1.2")),
            scopeKey = scope, networkLabel = label, now = 6000,
        )
        assertEquals(1, d.toInsert.size)
        assertEquals(1, d.present)
        assertFalse(d.newCount == 2)
    }
}
