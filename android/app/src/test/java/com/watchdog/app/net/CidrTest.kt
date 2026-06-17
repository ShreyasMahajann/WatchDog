package com.watchdog.app.net

import org.junit.Assert.assertEquals
import org.junit.Test

class CidrTest {

    @Test
    fun `slash 24 derives network and host range`() {
        val cidr = Cidr.of("192.168.1.37", 24)
        assertEquals(Cidr.ipToLong("192.168.1.0"), cidr.networkAddr)
        assertEquals(254L, cidr.hostCount)
        val hosts = cidr.hosts().toList()
        assertEquals("192.168.1.1", hosts.first())
        assertEquals("192.168.1.254", hosts.last())
        assertEquals(254, hosts.size)
    }

    @Test
    fun `ip long round trip`() {
        val ips = listOf("0.0.0.0", "10.0.0.1", "192.168.1.255", "255.255.255.255")
        for (ip in ips) assertEquals(ip, Cidr.longToIp(Cidr.ipToLong(ip)))
    }

    @Test
    fun `slash 31 and slash 32 include all addresses`() {
        assertEquals(2L, Cidr.of("192.168.1.4", 31).hostCount)
        assertEquals(1L, Cidr.of("192.168.1.9", 32).hostCount)
        assertEquals(listOf("192.168.1.9"), Cidr.of("192.168.1.9", 32).hosts().toList())
    }

    @Test
    fun `large subnet host count`() {
        assertEquals(65534L, Cidr.of("172.16.5.5", 16).hostCount)
    }
}
