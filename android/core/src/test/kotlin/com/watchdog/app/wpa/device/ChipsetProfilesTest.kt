package com.watchdog.app.wpa.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ChipsetProfilesTest {

    private fun device(vid: Int, pid: Int) = UsbDeviceInfo(
        vendorId = vid,
        productId = pid,
        productName = null,
        manufacturerName = null,
        deviceName = "/dev/bus/usb/001/002",
        interfaceClasses = emptyList(),
    )

    @Test
    fun `AR9271 primary id resolves to the AR9271 profile`() {
        assertSame(ChipsetProfiles.AR9271, ChipsetProfiles.lookup(0x0cf3, 0x9271))
    }

    @Test
    fun `MT7612U ids resolve to the MT7612U profile`() {
        assertSame(ChipsetProfiles.MT7612U, ChipsetProfiles.lookup(0x0e8d, 0x7612))
        assertSame(ChipsetProfiles.MT7612U, ChipsetProfiles.lookup(0x0e8d, 0x7601))
        assertSame(ChipsetProfiles.MT7612U, ChipsetProfiles.lookup(0x0e8d, 0x7610))
    }

    @Test
    fun `AR9271 combo id also resolves to the AR9271 profile`() {
        assertSame(ChipsetProfiles.AR9271, ChipsetProfiles.lookup(0x0cf3, 0x7015))
    }

    @Test
    fun `AR9271 profile advertises monitor and injection`() {
        val p = ChipsetProfiles.AR9271
        assertEquals("ath9k_htc", p.driver)
        assertTrue(p.monitorMode)
        assertTrue(p.packetInjection)
        assertTrue(p.handshakeCapture)
    }

    @Test
    fun `MT7612U profile advertises monitor and injection`() {
        val p = ChipsetProfiles.MT7612U
        assertEquals("mt76", p.driver)
        assertTrue(p.monitorMode)
        assertTrue(p.packetInjection)
        assertTrue(p.handshakeCapture)
    }

    @Test
    fun `unknown id resolves to null`() {
        assertNull(ChipsetProfiles.lookup(0x1234, 0x5678))
    }

    @Test
    fun `identify marks recognized and unrecognized devices`() {
        assertTrue(ChipsetProfiles.identify(device(0x0cf3, 0x9271)).isRecognized)
        val unknown = ChipsetProfiles.identify(device(0x1234, 0x5678))
        assertTrue(!unknown.isRecognized)
        assertNull(unknown.profile)
    }

    @Test
    fun `id string formats as lowercase hex`() {
        assertEquals("0cf3:9271", device(0x0cf3, 0x9271).idString)
    }
}
