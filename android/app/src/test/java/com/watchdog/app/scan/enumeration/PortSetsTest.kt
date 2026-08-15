package com.watchdog.app.scan.enumeration

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PortSetsTest {

    @Test
    fun serviceHint_namesCommonUnlabeledPorts() {
        assertEquals("rtsp", PortSets.serviceHint(554))
        assertEquals("daap", PortSets.serviceHint(3689))
        assertEquals("bittorrent", PortSets.serviceHint(6881))
        assertEquals("kerberos", PortSets.serviceHint(88))
        assertEquals("sip", PortSets.serviceHint(5060))
        assertEquals("airplay", PortSets.serviceHint(7000))
        assertEquals("upnp", PortSets.serviceHint(5000))
    }

    @Test
    fun serviceHint_unknownPortReturnsNull() {
        assertEquals(null, PortSets.serviceHint(64999))
    }

    @Test
    fun webLikelyPorts_includeAirplayAndControlPorts() {
        // Ports we should HTTP-probe so a Server header / title can identify them.
        assertTrue(PortSets.WEB_LIKELY.contains(5000))
        assertTrue(PortSets.WEB_LIKELY.contains(7000))
        assertTrue(PortSets.WEB_LIKELY.contains(8000))
        assertTrue(PortSets.WEB_LIKELY.contains(8080))
    }
}
