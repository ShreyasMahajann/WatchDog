package com.watchdog.app.ui.results

import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResultsFilterTest {

    private fun obs(
        host: String = "192.168.1.10",
        port: Int = 22,
        proto: String = "tcp",
        serviceName: String? = null,
        product: ProductIdentity? = null,
        evidence: ServiceEvidence? = null,
    ) = ServiceObservation(host, port, proto, serviceName, product, evidence)

    @Test
    fun serviceMatches_blankQueryMatchesEverything() {
        assertTrue(ResultsFilter.serviceMatches(obs(), ""))
        assertTrue(ResultsFilter.serviceMatches(obs(), "   "))
    }

    @Test
    fun serviceMatches_byPortNumber() {
        assertTrue(ResultsFilter.serviceMatches(obs(port = 7000), "7000"))
        assertFalse(ResultsFilter.serviceMatches(obs(port = 22), "7000"))
    }

    @Test
    fun serviceMatches_byServiceNameCaseInsensitive() {
        assertTrue(ResultsFilter.serviceMatches(obs(serviceName = "mysql"), "MYSQL"))
        assertTrue(ResultsFilter.serviceMatches(obs(serviceName = "http"), "ht"))
    }

    @Test
    fun serviceMatches_byProductAndVersion() {
        val p = ProductIdentity(product = "openssh", version = "8.2p1")
        assertTrue(ResultsFilter.serviceMatches(obs(product = p), "openssh"))
        assertTrue(ResultsFilter.serviceMatches(obs(product = p), "8.2"))
    }

    @Test
    fun serviceMatches_byBannerText() {
        val e = ServiceEvidence(banner = "dropbear 2016.74")
        assertTrue(ResultsFilter.serviceMatches(obs(evidence = e), "dropbear"))
    }

    @Test
    fun serviceMatches_byHttpPageTitle() {
        val e = ServiceEvidence(httpTitle = "Synology DiskStation")
        assertTrue(ResultsFilter.serviceMatches(obs(evidence = e), "synology"))
    }

    @Test
    fun serviceMatches_noMatchReturnsFalse() {
        assertFalse(ResultsFilter.serviceMatches(obs(port = 22, serviceName = "ssh"), "mysql"))
    }

    @Test
    fun hostMatches_byIpSubstringAndHostname() {
        assertTrue(ResultsFilter.hostMatches("172.31.225.164", null, "225."))
        assertTrue(ResultsFilter.hostMatches("10.0.0.5", "router.lan", "router"))
        assertFalse(ResultsFilter.hostMatches("10.0.0.5", "router.lan", "printer"))
    }

    @Test
    fun hostMatches_blankQueryMatchesEverything() {
        assertTrue(ResultsFilter.hostMatches("10.0.0.5", null, ""))
    }

    @Test
    fun groupByService_groupsByPortProtoNameAndCountsDistinctHosts() {
        val list = listOf(
            obs(host = "10.0.0.1", port = 7000),
            obs(host = "10.0.0.2", port = 7000),
            obs(host = "10.0.0.2", port = 7000), // duplicate host on same port
            obs(host = "10.0.0.3", port = 3306, serviceName = "mysql"),
        )
        val groups = ResultsFilter.groupByService(list)
        val g7000 = groups.first { it.port == 7000 }
        assertEquals(2, g7000.hosts.size)
        // most-widespread first
        assertEquals(7000, groups.first().port)
    }

    @Test
    fun serviceGroupMatches_byPortServiceNameOrHostIp() {
        val g = ServiceGroup(port = 3306, proto = "tcp", serviceName = "mysql", hosts = listOf("10.0.0.3"))
        assertTrue(ResultsFilter.serviceGroupMatches(g, "3306"))
        assertTrue(ResultsFilter.serviceGroupMatches(g, "mysql"))
        assertTrue(ResultsFilter.serviceGroupMatches(g, "10.0.0.3"))
        assertFalse(ResultsFilter.serviceGroupMatches(g, "ssh"))
    }
}
